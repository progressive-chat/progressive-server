// user_directory.cpp - Matrix User Directory and Profile Search
// Implements user directory management, profile search, directory rebuild,
// incremental updates, deactivation handling, and per-room isolation.
// Equivalent to synapse/handlers/user_directory.py + synapse/storage/databases/main/user_directory.py
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
namespace chr = std::chrono;

// ============================================================================
// Forward declarations
// ============================================================================
class UserDirectoryManager;
class UserDirectorySearchEngine;
class UserDirectoryRebuilder;
class UserDirectoryIncrementalUpdater;
class UserDirectorySearchIndex;
class UserDirectoryRoomIsolator;
class UserDirectoryProfileRanker;
class UserDirectoryDeactivationHandler;
class UserDirectoryBatchProcessor;
class UserDirectoryCacheManager;
class UserDirectoryStatsCollector;

// ============================================================================
// Utility: string and time helpers
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

std::string to_upper(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), ::toupper);
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
  auto now = chr::system_clock::now();
  auto t = chr::system_clock::to_time_t(now);
  auto ms = chr::duration_cast<chr::milliseconds>(
                now.time_since_epoch()) %
            1000;
  std::tm tm_buf;
  gmtime_r(&t, &tm_buf);
  std::ostringstream oss;
  oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%S") << '.' << std::setw(3)
      << std::setfill('0') << ms.count() << "Z";
  return oss.str();
}

int64_t current_time_ms() {
  return chr::duration_cast<chr::milliseconds>(
             chr::system_clock::now().time_since_epoch())
      .count();
}

int64_t current_time_sec() {
  return chr::duration_cast<chr::seconds>(
             chr::system_clock::now().time_since_epoch())
      .count();
}

// Lexicographic substring match (case-insensitive)
bool fuzzy_match(const std::string& text, const std::string& pattern) {
  std::string t = to_lower(text);
  std::string p = to_lower(pattern);
  return t.find(p) != std::string::npos;
}

// Prefix match (case-insensitive)
bool prefix_match(const std::string& text, const std::string& prefix) {
  std::string t = to_lower(text);
  std::string p = to_lower(prefix);
  return t.size() >= p.size() && t.substr(0, p.size()) == p;
}

// Check if user_id is a valid Matrix user ID (@localpart:domain)
bool is_valid_user_id(const std::string& user_id) {
  if (user_id.empty() || user_id[0] != '@') return false;
  auto colon_pos = user_id.find(':');
  if (colon_pos == std::string::npos || colon_pos <= 1 ||
      colon_pos == user_id.size() - 1)
    return false;
  return true;
}

// Check if room_id is a valid Matrix room ID (!localpart:domain)
bool is_valid_room_id(const std::string& room_id) {
  if (room_id.empty() || room_id[0] != '!') return false;
  auto colon_pos = room_id.find(':');
  if (colon_pos == std::string::npos || colon_pos <= 1 ||
      colon_pos == room_id.size() - 1)
    return false;
  return true;
}

// Extract domain from a Matrix ID
std::string extract_domain(const std::string& mxid) {
  auto colon_pos = mxid.find(':');
  if (colon_pos != std::string::npos && colon_pos + 1 < mxid.size())
    return mxid.substr(colon_pos + 1);
  return "";
}

// Extract localpart from a Matrix user ID
std::string extract_localpart(const std::string& user_id) {
  if (user_id.empty() || user_id[0] != '@') return "";
  auto colon_pos = user_id.find(':');
  if (colon_pos == std::string::npos) return user_id.substr(1);
  return user_id.substr(1, colon_pos - 1);
}

} // anonymous namespace

// ============================================================================
// UserDirectoryEntry - Represents a single entry in the user directory
// ============================================================================
struct UserDirectoryEntry {
  std::string user_id;
  std::string display_name;
  std::optional<std::string> avatar_url;
  int64_t shared_rooms{0};
  bool deactivated{false};
  bool is_public{true};
  int64_t last_updated_ts{0};
  int64_t created_ts{0};
  std::vector<std::string> public_room_ids;

  json to_json() const {
    json j;
    j["user_id"] = user_id;
    j["display_name"] = display_name;
    if (avatar_url.has_value()) j["avatar_url"] = avatar_url.value();
    j["shared_rooms"] = shared_rooms;
    j["deactivated"] = deactivated;
    return j;
  }

  static UserDirectoryEntry from_json(const json& j) {
    UserDirectoryEntry e;
    e.user_id = j.value("user_id", "");
    e.display_name = j.value("display_name", "");
    if (j.contains("avatar_url") && !j["avatar_url"].is_null())
      e.avatar_url = j["avatar_url"].get<std::string>();
    e.shared_rooms = j.value("shared_rooms", int64_t{0});
    e.deactivated = j.value("deactivated", false);
    return e;
  }
};

// ============================================================================
// UserDirectorySearchQuery - Search parameters for directory lookup
// ============================================================================
struct UserDirectorySearchQuery {
  std::string search_term;
  int limit{10};
  int offset{0};
  std::optional<std::string> order_by;  // "display_name", "shared_rooms", "recent"
  bool ascending{true};
  bool include_deactivated{false};
  bool search_by_userid{false};
  bool exact_match{false};
  std::optional<std::string> requester_id;  // for shared rooms filtering
  std::optional<std::vector<std::string>> room_filter;  // only in these rooms
  std::optional<std::string> domain_filter;  // only users from this domain

  static UserDirectorySearchQuery create(const std::string& term, int l = 10) {
    UserDirectorySearchQuery q;
    q.search_term = term;
    q.limit = l;
    return q;
  }
};

// ============================================================================
// UserDirectorySearchResult - A single search result with ranking metadata
// ============================================================================
struct UserDirectorySearchResult {
  UserDirectoryEntry entry;
  double relevance_score{0.0};
  int64_t shared_room_count{0};
  std::vector<std::string> shared_room_ids;
  bool is_exact_match{false};
  bool is_prefix_match{false};

  json to_json() const {
    json j = entry.to_json();
    j["relevance_score"] = relevance_score;
    j["shared_room_count"] = shared_room_count;
    return j;
  }
};

// ============================================================================
// SharedRoomsTracker - Tracks shared rooms between users for ranking
// ============================================================================
class SharedRoomsTracker {
public:
  SharedRoomsTracker() = default;

  void add_membership(const std::string& user_id, const std::string& room_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    user_rooms_[user_id].insert(room_id);
    room_users_[room_id].insert(user_id);
  }

  void remove_membership(const std::string& user_id, const std::string& room_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = user_rooms_.find(user_id);
    if (it != user_rooms_.end()) {
      it->second.erase(room_id);
      if (it->second.empty()) user_rooms_.erase(it);
    }
    auto rit = room_users_.find(room_id);
    if (rit != room_users_.end()) {
      rit->second.erase(user_id);
      if (rit->second.empty()) room_users_.erase(rit);
    }
  }

  void remove_user(const std::string& user_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = user_rooms_.find(user_id);
    if (it != user_rooms_.end()) {
      for (const auto& room_id : it->second) {
        auto rit = room_users_.find(room_id);
        if (rit != room_users_.end()) rit->second.erase(user_id);
      }
      user_rooms_.erase(it);
    }
  }

  int64_t count_shared_rooms(const std::string& user_a,
                              const std::string& user_b) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it_a = user_rooms_.find(user_a);
    auto it_b = user_rooms_.find(user_b);
    if (it_a == user_rooms_.end() || it_b == user_rooms_.end()) return 0;
    int64_t count = 0;
    for (const auto& room_id : it_a->second) {
      if (it_b->second.count(room_id)) count++;
    }
    return count;
  }

  std::vector<std::string> get_shared_rooms(const std::string& user_a,
                                              const std::string& user_b) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    auto it_a = user_rooms_.find(user_a);
    auto it_b = user_rooms_.find(user_b);
    if (it_a == user_rooms_.end() || it_b == user_rooms_.end()) return result;
    for (const auto& room_id : it_a->second) {
      if (it_b->second.count(room_id)) result.push_back(room_id);
    }
    return result;
  }

  std::set<std::string> get_user_rooms(const std::string& user_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = user_rooms_.find(user_id);
    if (it != user_rooms_.end()) return it->second;
    return {};
  }

  std::set<std::string> get_room_users(const std::string& room_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = room_users_.find(room_id);
    if (it != room_users_.end()) return it->second;
    return {};
  }

  size_t total_rooms() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return room_users_.size();
  }

  size_t total_users() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return user_rooms_.size();
  }

  void clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    user_rooms_.clear();
    room_users_.clear();
  }

private:
  mutable std::mutex mutex_;
  std::unordered_map<std::string, std::set<std::string>> user_rooms_;
  std::unordered_map<std::string, std::set<std::string>> room_users_;
};

// ============================================================================
// UserDirectorySearchIndex - In-memory search index for fast lookups
// ============================================================================
class UserDirectorySearchIndex {
public:
  UserDirectorySearchIndex() = default;

  void index_user(const UserDirectoryEntry& entry) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    entries_[entry.user_id] = entry;

    // Index by display name tokens
    auto tokens = tokenize(entry.display_name);
    for (const auto& token : tokens) {
      display_name_index_[token].insert(entry.user_id);
    }

    // Index by user ID parts
    auto userid_tokens = tokenize(entry.user_id);
    for (const auto& token : userid_tokens) {
      userid_index_[token].insert(entry.user_id);
    }

    // Index by domain
    std::string domain = extract_domain(entry.user_id);
    if (!domain.empty()) {
      domain_index_[domain].insert(entry.user_id);
    }
  }

  void remove_user(const std::string& user_id) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = entries_.find(user_id);
    if (it == entries_.end()) return;

    auto& entry = it->second;
    auto tokens = tokenize(entry.display_name);
    for (const auto& token : tokens) {
      auto t = display_name_index_.find(token);
      if (t != display_name_index_.end()) {
        t->second.erase(user_id);
        if (t->second.empty()) display_name_index_.erase(t);
      }
    }

    auto userid_tokens = tokenize(entry.user_id);
    for (const auto& token : userid_tokens) {
      auto t = userid_index_.find(token);
      if (t != userid_index_.end()) {
        t->second.erase(user_id);
        if (t->second.empty()) userid_index_.erase(t);
      }
    }

    std::string domain = extract_domain(entry.user_id);
    if (!domain.empty()) {
      auto d = domain_index_.find(domain);
      if (d != domain_index_.end()) {
        d->second.erase(user_id);
        if (d->second.empty()) domain_index_.erase(d);
      }
    }

    entries_.erase(it);
  }

  void update_user(const std::string& user_id, const std::string& display_name) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = entries_.find(user_id);
    if (it == entries_.end()) {
      UserDirectoryEntry e;
      e.user_id = user_id;
      e.display_name = display_name;
      index_user(e);
      return;
    }

    // Remove old display name tokens
    auto old_tokens = tokenize(it->second.display_name);
    for (const auto& token : old_tokens) {
      auto t = display_name_index_.find(token);
      if (t != display_name_index_.end()) {
        t->second.erase(user_id);
        if (t->second.empty()) display_name_index_.erase(t);
      }
    }

    // Update and re-index
    it->second.display_name = display_name;
    auto new_tokens = tokenize(display_name);
    for (const auto& token : new_tokens) {
      display_name_index_[token].insert(user_id);
    }
  }

  std::vector<UserDirectoryEntry> search(const UserDirectorySearchQuery& query) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::unordered_set<std::string> candidate_ids;

    if (query.exact_match) {
      // Exact match: search in display_name_index_
      auto it = display_name_index_.find(to_lower(query.search_term));
      if (it != display_name_index_.end()) {
        candidate_ids = it->second;
      }
      // Also exact match by user ID
      auto uit = userid_index_.find(to_lower(query.search_term));
      if (uit != userid_index_.end()) {
        candidate_ids.insert(uit->second.begin(), uit->second.end());
      }
    } else if (query.search_by_userid) {
      // Prefix match on user ID tokens
      std::string term = to_lower(query.search_term);
      for (const auto& [token, users] : userid_index_) {
        if (token.find(term) != std::string::npos) {
          candidate_ids.insert(users.begin(), users.end());
        }
      }
    } else {
      // Fuzzy match on display name tokens
      std::string term = to_lower(query.search_term);
      auto search_tokens = tokenize(term);
      for (const auto& search_token : search_tokens) {
        for (const auto& [token, users] : display_name_index_) {
          if (token.find(search_token) != std::string::npos) {
            candidate_ids.insert(users.begin(), users.end());
          }
        }
      }
    }

    // Filter by domain if specified
    std::vector<UserDirectoryEntry> results;
    for (const auto& user_id : candidate_ids) {
      auto it = entries_.find(user_id);
      if (it == entries_.end()) continue;

      if (query.domain_filter.has_value()) {
        if (extract_domain(user_id) != query.domain_filter.value()) continue;
      }

      if (!query.include_deactivated && it->second.deactivated) continue;

      results.push_back(it->second);
    }

    return results;
  }

  std::optional<UserDirectoryEntry> get_entry(const std::string& user_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = entries_.find(user_id);
    if (it != entries_.end()) return it->second;
    return std::nullopt;
  }

  size_t size() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return entries_.size();
  }

  void clear() {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    entries_.clear();
    display_name_index_.clear();
    userid_index_.clear();
    domain_index_.clear();
  }

  std::vector<std::string> get_all_user_ids() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::vector<std::string> ids;
    ids.reserve(entries_.size());
    for (const auto& [id, _] : entries_) ids.push_back(id);
    return ids;
  }

private:
  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, UserDirectoryEntry> entries_;
  std::unordered_map<std::string, std::unordered_set<std::string>> display_name_index_;
  std::unordered_map<std::string, std::unordered_set<std::string>> userid_index_;
  std::unordered_map<std::string, std::unordered_set<std::string>> domain_index_;

  static std::vector<std::string> tokenize(const std::string& text) {
    std::vector<std::string> tokens;
    std::string lower = to_lower(text);
    std::stringstream ss(lower);
    std::string token;
    // Split by whitespace and punctuation
    while (std::getline(ss, token, ' ')) {
      // Further split by punctuation
      size_t start = 0;
      for (size_t i = 0; i <= token.size(); i++) {
        if (i == token.size() || !std::isalnum(static_cast<unsigned char>(token[i]))) {
          if (i > start) {
            std::string sub = token.substr(start, i - start);
            if (sub.size() >= 2) tokens.push_back(sub);
          }
          start = i + 1;
        }
      }
    }
    // Also add the full string for exact match
    if (lower.size() >= 2 && !lower.empty())
      tokens.push_back(lower);
    return tokens;
  }
};

// ============================================================================
// UserDirectoryRoomIsolator - Handles per-room visibility/isolation
// Equivalent to synapse/handlers/user_directory.py room visibility checks
// ============================================================================
class UserDirectoryRoomIsolator {
public:
  UserDirectoryRoomIsolator() = default;

  // Determine if a room is "public" for user directory purposes
  enum class RoomVisibility {
    PUBLIC,          // Everyone can see members
    SHARED_ONLY,     // Only members can see other members
    PRIVATE,         // Nobody can see members via directory
    WORLD_READABLE,  // Anyone can read the room
  };

  void set_room_visibility(const std::string& room_id,
                            RoomVisibility visibility) {
    std::lock_guard<std::mutex> lock(mutex_);
    room_visibility_[room_id] = visibility;
  }

  RoomVisibility get_room_visibility(const std::string& room_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = room_visibility_.find(room_id);
    if (it != room_visibility_.end()) return it->second;
    return RoomVisibility::PUBLIC;  // Default: public
  }

  bool is_room_public_for_directory(const std::string& room_id) const {
    auto vis = get_room_visibility(room_id);
    return vis == RoomVisibility::PUBLIC ||
           vis == RoomVisibility::WORLD_READABLE;
  }

  // Check if a requesting user can see the target user in directory context
  bool can_see_user(const std::string& requester_id,
                    const std::string& target_id,
                    const SharedRoomsTracker& tracker) {
    if (requester_id == target_id) return true;

    auto target_rooms = tracker.get_user_rooms(target_id);
    for (const auto& room_id : target_rooms) {
      if (is_room_public_for_directory(room_id)) return true;
    }

    // If the requester shares any room with the target
    auto shared = tracker.get_shared_rooms(requester_id, target_id);
    return !shared.empty();
  }

  // Get the list of rooms the requester should be able to see the target user from
  std::vector<std::string> get_visible_shared_rooms(
      const std::string& requester_id,
      const std::string& target_id,
      const SharedRoomsTracker& tracker) {
    std::vector<std::string> result;
    auto shared = tracker.get_shared_rooms(requester_id, target_id);
    for (const auto& room_id : shared) {
      auto vis = get_room_visibility(room_id);
      if (vis == RoomVisibility::PUBLIC ||
          vis == RoomVisibility::SHARED_ONLY ||
          vis == RoomVisibility::WORLD_READABLE) {
        result.push_back(room_id);
      }
    }
    return result;
  }

  // Check if a room is isolated (private) and should be excluded from directory
  bool should_exclude_from_directory(const std::string& room_id) const {
    auto vis = get_room_visibility(room_id);
    return vis == RoomVisibility::PRIVATE;
  }

  void remove_room(const std::string& room_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    room_visibility_.erase(room_id);
  }

  static std::string visibility_to_string(RoomVisibility v) {
    switch (v) {
      case RoomVisibility::PUBLIC: return "public";
      case RoomVisibility::SHARED_ONLY: return "shared_only";
      case RoomVisibility::PRIVATE: return "private";
      case RoomVisibility::WORLD_READABLE: return "world_readable";
    }
    return "unknown";
  }

  static RoomVisibility string_to_visibility(const std::string& s) {
    if (s == "public") return RoomVisibility::PUBLIC;
    if (s == "shared_only") return RoomVisibility::SHARED_ONLY;
    if (s == "private") return RoomVisibility::PRIVATE;
    if (s == "world_readable") return RoomVisibility::WORLD_READABLE;
    return RoomVisibility::PUBLIC;
  }

private:
  mutable std::mutex mutex_;
  std::unordered_map<std::string, RoomVisibility> room_visibility_;
};

// ============================================================================
// UserDirectoryProfileRanker - Ranks search results by relevance
// ============================================================================
class UserDirectoryProfileRanker {
public:
  UserDirectoryProfileRanker() = default;

  void rank(std::vector<UserDirectorySearchResult>& results,
            const UserDirectorySearchQuery& query,
            const SharedRoomsTracker& shared_tracker) {

    std::string term = to_lower(query.search_term);

    // Calculate relevance score for each result
    for (auto& result : results) {
      double score = 0.0;

      // Exact display_name match: highest boost
      if (to_lower(result.entry.display_name) == term) {
        score += 100.0;
        result.is_exact_match = true;
      }

      // Prefix match on display_name
      if (prefix_match(result.entry.display_name, term)) {
        score += 50.0;
        result.is_prefix_match = true;
      }

      // Substring match on display_name
      if (fuzzy_match(result.entry.display_name, term)) {
        score += 20.0;
      }

      // Exact user_id match
      if (to_lower(result.entry.user_id) == term) {
        score += 90.0;
        result.is_exact_match = true;
      }

      // Substring match on user_id (e.g., searching for localpart)
      if (fuzzy_match(result.entry.user_id, term)) {
        score += 15.0;
      }

      // Shared rooms boost
      if (query.requester_id.has_value()) {
        int64_t shared = shared_tracker.count_shared_rooms(
            query.requester_id.value(), result.entry.user_id);
        result.shared_room_count = shared;
        result.shared_room_ids =
            shared_tracker.get_shared_rooms(query.requester_id.value(),
                                             result.entry.user_id);
        score += static_cast<double>(shared) * 5.0;
      }

      // Display name length penalty (shorter names are more likely relevant)
      if (!result.entry.display_name.empty()) {
        score -= std::min(static_cast<double>(result.entry.display_name.size()),
                          10.0) * 0.5;
      }

      result.relevance_score = score;
    }

    // Sort by relevance score descending
    std::sort(results.begin(), results.end(),
              [](const UserDirectorySearchResult& a,
                 const UserDirectorySearchResult& b) {
                if (std::abs(a.relevance_score - b.relevance_score) > 0.001)
                  return a.relevance_score > b.relevance_score;
                // Tiebreak: more shared rooms
                if (a.shared_room_count != b.shared_room_count)
                  return a.shared_room_count > b.shared_room_count;
                // Tiebreak: display_name alphabetically
                return a.entry.display_name < b.entry.display_name;
              });
  }
};

// ============================================================================
// UserDirectoryDeactivationHandler - Handles user deactivation events
// ============================================================================
class UserDirectoryDeactivationHandler {
public:
  UserDirectoryDeactivationHandler() = default;

  struct DeactivationRecord {
    std::string user_id;
    int64_t deactivated_at;
    std::string reason;
    bool is_deactivated{false};
  };

  // Mark a user as deactivated in the directory
  void deactivate_user(const std::string& user_id,
                       const std::string& reason = "") {
    std::lock_guard<std::mutex> lock(mutex_);
    DeactivationRecord rec;
    rec.user_id = user_id;
    rec.deactivated_at = current_time_ms();
    rec.reason = reason;
    rec.is_deactivated = true;
    deactivated_users_[user_id] = rec;
  }

  // Reactivate a previously deactivated user
  void reactivate_user(const std::string& user_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    deactivated_users_.erase(user_id);
    reactivation_log_[user_id] = current_time_ms();
  }

  bool is_deactivated(const std::string& user_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return deactivated_users_.count(user_id) > 0;
  }

  std::optional<DeactivationRecord> get_deactivation_record(
      const std::string& user_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = deactivated_users_.find(user_id);
    if (it != deactivated_users_.end()) return it->second;
    return std::nullopt;
  }

  std::vector<DeactivationRecord> get_all_deactivated_users() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<DeactivationRecord> result;
    result.reserve(deactivated_users_.size());
    for (const auto& [_, rec] : deactivated_users_) result.push_back(rec);
    return result;
  }

  // Get the set of all deactivated user IDs
  std::unordered_set<std::string> get_deactivated_user_ids() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::unordered_set<std::string> ids;
    for (const auto& [id, _] : deactivated_users_) ids.insert(id);
    return ids;
  }

  bool was_recently_reactivated(const std::string& user_id,
                                 int64_t within_ms = 3600000) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = reactivation_log_.find(user_id);
    if (it != reactivation_log_.end()) {
      return (current_time_ms() - it->second) < within_ms;
    }
    return false;
  }

  size_t deactivated_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return deactivated_users_.size();
  }

  void clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    deactivated_users_.clear();
    reactivation_log_.clear();
  }

private:
  mutable std::mutex mutex_;
  std::unordered_map<std::string, DeactivationRecord> deactivated_users_;
  std::unordered_map<std::string, int64_t> reactivation_log_;
};

// ============================================================================
// UserDirectoryCacheManager - LRU cache for frequently accessed directory data
// ============================================================================
class UserDirectoryCacheManager {
public:
  explicit UserDirectoryCacheManager(size_t max_size = 10000)
      : max_size_(max_size) {}

  void put(const std::string& key, const UserDirectoryEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_map_.find(key);
    if (it != cache_map_.end()) {
      lru_list_.erase(it->second);
    } else if (cache_map_.size() >= max_size_) {
      auto last = lru_list_.back();
      cache_map_.erase(last);
      lru_list_.pop_back();
    }
    lru_list_.push_front(key);
    cache_map_[key] = {lru_list_.begin(), entry};
  }

  std::optional<UserDirectoryEntry> get(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_map_.find(key);
    if (it == cache_map_.end()) return std::nullopt;
    lru_list_.erase(it->second.first);
    lru_list_.push_front(key);
    it->second.first = lru_list_.begin();
    return it->second.second;
  }

  void remove(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_map_.find(key);
    if (it != cache_map_.end()) {
      lru_list_.erase(it->second.first);
      cache_map_.erase(it);
    }
  }

  void invalidate() {
    std::lock_guard<std::mutex> lock(mutex_);
    cache_map_.clear();
    lru_list_.clear();
  }

  size_t size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return cache_map_.size();
  }

  bool contains(const std::string& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return cache_map_.count(key) > 0;
  }

private:
  mutable std::mutex mutex_;
  size_t max_size_;
  std::list<std::string> lru_list_;
  struct CacheEntry {
    std::list<std::string>::iterator first;
    UserDirectoryEntry second;
  };
  std::unordered_map<std::string, CacheEntry> cache_map_;
};

// ============================================================================
// UserDirectoryBatchProcessor - Handles batch operations on directory
// ============================================================================
class UserDirectoryBatchProcessor {
public:
  UserDirectoryBatchProcessor() = default;

  struct BatchOperation {
    enum Type { ADD, UPDATE, REMOVE, DEACTIVATE, REACTIVATE };
    Type type;
    std::string user_id;
    std::string display_name;
    std::optional<std::string> avatar_url;

    static BatchOperation add(const std::string& uid, const std::string& name,
                               const std::optional<std::string>& avatar) {
      BatchOperation op;
      op.type = ADD;
      op.user_id = uid;
      op.display_name = name;
      op.avatar_url = avatar;
      return op;
    }

    static BatchOperation update(const std::string& uid,
                                  const std::string& name,
                                  const std::optional<std::string>& avatar) {
      BatchOperation op;
      op.type = UPDATE;
      op.user_id = uid;
      op.display_name = name;
      op.avatar_url = avatar;
      return op;
    }

    static BatchOperation remove(const std::string& uid) {
      BatchOperation op;
      op.type = REMOVE;
      op.user_id = uid;
      return op;
    }

    static BatchOperation deactivate(const std::string& uid) {
      BatchOperation op;
      op.type = DEACTIVATE;
      op.user_id = uid;
      return op;
    }

    static BatchOperation reactivate(const std::string& uid) {
      BatchOperation op;
      op.type = REACTIVATE;
      op.user_id = uid;
      return op;
    }
  };

  void enqueue(const BatchOperation& op) {
    std::lock_guard<std::mutex> lock(mutex_);
    queue_.push(op);
  }

  void enqueue_bulk(const std::vector<BatchOperation>& ops) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& op : ops) queue_.push(op);
  }

  std::optional<BatchOperation> dequeue() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (queue_.empty()) return std::nullopt;
    auto op = queue_.front();
    queue_.pop();
    return op;
  }

  std::vector<BatchOperation> dequeue_all() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<BatchOperation> ops;
    while (!queue_.empty()) {
      ops.push_back(queue_.front());
      queue_.pop();
    }
    return ops;
  }

  size_t pending() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size();
  }

  void clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::queue<BatchOperation> empty;
    std::swap(queue_, empty);
  }

private:
  mutable std::mutex mutex_;
  std::queue<BatchOperation> queue_;
};

// ============================================================================
// UserDirectoryStatsCollector - Collects and reports statistics
// ============================================================================
class UserDirectoryStatsCollector {
public:
  UserDirectoryStatsCollector() = default;

  struct DirectoryStats {
    int64_t total_users{0};
    int64_t active_users{0};
    int64_t deactivated_users{0};
    int64_t public_users{0};
    int64_t total_rooms_indexed{0};
    int64_t total_searches{0};
    int64_t total_lookups{0};
    int64_t cache_hits{0};
    int64_t cache_misses{0};
    int64_t rebuilds_performed{0};
    int64_t last_rebuild_ts{0};
    int64_t incremental_updates{0};
    double avg_search_time_ms{0.0};
  };

  void record_search(int64_t time_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.total_searches++;
    stats_.avg_search_time_ms =
        (stats_.avg_search_time_ms * (stats_.total_searches - 1) + time_ms) /
        stats_.total_searches;
  }

  void record_lookup() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.total_lookups++;
  }

  void record_cache_hit() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.cache_hits++;
  }

  void record_cache_miss() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.cache_misses++;
  }

  void record_rebuild() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.rebuilds_performed++;
    stats_.last_rebuild_ts = current_time_ms();
  }

  void record_incremental_update() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.incremental_updates++;
  }

  void set_user_counts(int64_t total, int64_t active, int64_t deactivated,
                        int64_t public_users) {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.total_users = total;
    stats_.active_users = active;
    stats_.deactivated_users = deactivated;
    stats_.public_users = public_users;
  }

  void set_total_rooms_indexed(int64_t rooms) {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.total_rooms_indexed = rooms;
  }

  DirectoryStats get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
  }

  json get_stats_json() const {
    auto s = get_stats();
    json j;
    j["total_users"] = s.total_users;
    j["active_users"] = s.active_users;
    j["deactivated_users"] = s.deactivated_users;
    j["public_users"] = s.public_users;
    j["total_rooms_indexed"] = s.total_rooms_indexed;
    j["total_searches"] = s.total_searches;
    j["total_lookups"] = s.total_lookups;
    j["cache_hits"] = s.cache_hits;
    j["cache_misses"] = s.cache_misses;
    j["cache_hit_ratio"] =
        s.cache_hits + s.cache_misses > 0
            ? static_cast<double>(s.cache_hits) /
                  (s.cache_hits + s.cache_misses)
            : 0.0;
    j["rebuilds_performed"] = s.rebuilds_performed;
    j["last_rebuild_ts"] = s.last_rebuild_ts;
    j["incremental_updates"] = s.incremental_updates;
    j["avg_search_time_ms"] = s.avg_search_time_ms;
    return j;
  }

  void reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_ = DirectoryStats{};
  }

private:
  mutable std::mutex mutex_;
  DirectoryStats stats_;
};

// ============================================================================
// UserDirectoryRebuilder - Full rebuild of user directory from DB
// Equivalent to synapse/storage/databases/main/user_directory.py:rebuild
// ============================================================================
class UserDirectoryRebuilder {
public:
  UserDirectoryRebuilder(
      UserDirectorySearchIndex& index,
      SharedRoomsTracker& shared_tracker,
      UserDirectoryDeactivationHandler& deactivation_handler,
      UserDirectoryRoomIsolator& isolator,
      UserDirectoryStatsCollector& stats,
      UserDirectoryCacheManager& cache)
      : index_(index),
        shared_tracker_(shared_tracker),
        deactivation_handler_(deactivation_handler),
        isolator_(isolator),
        stats_(stats),
        cache_(cache) {}

  // Full rebuild: clear and repopulate the user directory from source data
  struct RebuildConfig {
    bool index_all_users{true};
    bool include_deactivated{false};
    bool rebuild_shared_rooms{true};
    bool rebuild_search_index{true};
    int batch_size{1000};
    bool parallel{false};
    int parallel_workers{4};
  };

  struct RebuildProgress {
    int64_t total_users{0};
    int64_t processed_users{0};
    int64_t total_rooms{0};
    int64_t processed_rooms{0};
    bool complete{false};
    int64_t started_at{0};
    int64_t completed_at{0};
    std::vector<std::string> errors;

    double percent_complete() const {
      if (total_users == 0) return 0.0;
      return static_cast<double>(processed_users) / total_users * 100.0;
    }
  };

  // Rebuild from provided user and room data
  void rebuild(
      const std::vector<UserDirectoryEntry>& users,
      const std::vector<std::pair<std::string, std::string>>& memberships,
      const RebuildConfig& config = RebuildConfig{}) {

    RebuildProgress progress;
    progress.started_at = current_time_ms();

    // Clear existing data
    if (config.rebuild_search_index) {
      index_.clear();
    }
    if (config.rebuild_shared_rooms) {
      shared_tracker_.clear();
    }
    cache_.invalidate();

    progress.total_users = users.size();
    progress.total_rooms = 0;

    // Index users
    std::set<std::string> room_ids;
    for (const auto& user : users) {
      if (!config.include_deactivated && deactivation_handler_.is_deactivated(
                                             user.user_id)) {
        progress.processed_users++;
        continue;
      }

      index_.index_user(user);
      cache_.put(user.user_id, user);
      progress.processed_users++;
    }

    // Index memberships
    for (const auto& [user_id, room_id] : memberships) {
      shared_tracker_.add_membership(user_id, room_id);
      room_ids.insert(room_id);
    }
    progress.processed_rooms = room_ids.size();

    progress.complete = true;
    progress.completed_at = current_time_ms();
    stats_.record_rebuild();
    stats_.set_user_counts(users.size(),
                            users.size() - deactivation_handler_.deactivated_count(),
                            deactivation_handler_.deactivated_count(),
                            0);  // public_users will be updated by search engine
    stats_.set_total_rooms_indexed(room_ids.size());

    last_progress_ = progress;
  }

  // Incremental rebuild: only refresh a specific user
  void rebuild_user(const UserDirectoryEntry& entry) {
    // Remove old entry
    index_.remove_user(entry.user_id);
    cache_.remove(entry.user_id);
    shared_tracker_.remove_user(entry.user_id);

    // Add new entry
    if (!entry.deactivated) {
      index_.index_user(entry);
      cache_.put(entry.user_id, entry);
      stats_.record_incremental_update();
    }
  }

  // Rebuild shared rooms for a user from room memberships
  void rebuild_user_shared_rooms(
      const std::string& user_id,
      const std::vector<std::string>& room_ids) {
    shared_tracker_.remove_user(user_id);
    for (const auto& room_id : room_ids) {
      shared_tracker_.add_membership(user_id, room_id);
    }
    stats_.record_incremental_update();
  }

  // Rebuild users in a room (e.g., after room visibility change)
  void rebuild_room_users(
      const std::string& room_id,
      const std::vector<std::string>& user_ids,
      const std::vector<UserDirectoryEntry>& user_entries) {

    for (size_t i = 0; i < user_ids.size() && i < user_entries.size(); i++) {
      shared_tracker_.add_membership(user_ids[i], room_id);
      index_.index_user(user_entries[i]);
      cache_.put(user_ids[i], user_entries[i]);
    }
    stats_.record_incremental_update();
  }

  RebuildProgress get_last_progress() const { return last_progress_; }

private:
  UserDirectorySearchIndex& index_;
  SharedRoomsTracker& shared_tracker_;
  UserDirectoryDeactivationHandler& deactivation_handler_;
  UserDirectoryRoomIsolator& isolator_;
  UserDirectoryStatsCollector& stats_;
  UserDirectoryCacheManager& cache_;
  RebuildProgress last_progress_;
};

// ============================================================================
// UserDirectoryIncrementalUpdater - Handles incremental updates
// ============================================================================
class UserDirectoryIncrementalUpdater {
public:
  UserDirectoryIncrementalUpdater(
      UserDirectorySearchIndex& index,
      SharedRoomsTracker& shared_tracker,
      UserDirectoryDeactivationHandler& deactivation_handler,
      UserDirectoryRoomIsolator& isolator,
      UserDirectoryCacheManager& cache,
      UserDirectoryStatsCollector& stats)
      : index_(index),
        shared_tracker_(shared_tracker),
        deactivation_handler_(deactivation_handler),
        isolator_(isolator),
        cache_(cache),
        stats_(stats) {}

  // Handle a profile change (display_name or avatar_url)
  void handle_profile_change(const std::string& user_id,
                              const std::string& display_name,
                              const std::optional<std::string>& avatar_url) {
    if (deactivation_handler_.is_deactivated(user_id)) return;

    auto existing = index_.get_entry(user_id);
    UserDirectoryEntry entry;
    entry.user_id = user_id;
    entry.display_name = display_name;
    entry.avatar_url = avatar_url;
    entry.last_updated_ts = current_time_ms();

    if (existing.has_value()) {
      entry.shared_rooms = existing->shared_rooms;
      entry.created_ts = existing->created_ts;
      entry.deactivated = existing->deactivated;
      entry.public_room_ids = existing->public_room_ids;
    } else {
      entry.created_ts = current_time_ms();
    }

    index_.update_user(user_id, display_name);
    cache_.put(user_id, entry);
    stats_.record_incremental_update();
  }

  // Handle a user joining a room
  void handle_room_join(const std::string& user_id, const std::string& room_id) {
    if (deactivation_handler_.is_deactivated(user_id)) return;

    shared_tracker_.add_membership(user_id, room_id);

    // Update the shared room count in the search index
    auto existing = index_.get_entry(user_id);
    if (existing.has_value()) {
      existing->shared_rooms = shared_tracker_.get_user_rooms(user_id).size();
      cache_.put(user_id, existing.value());
    }
    stats_.record_incremental_update();
  }

  // Handle a user leaving a room
  void handle_room_leave(const std::string& user_id, const std::string& room_id) {
    if (deactivation_handler_.is_deactivated(user_id)) return;

    shared_tracker_.remove_membership(user_id, room_id);

    auto existing = index_.get_entry(user_id);
    if (existing.has_value()) {
      existing->shared_rooms = shared_tracker_.get_user_rooms(user_id).size();
      cache_.put(user_id, existing.value());
    }
    stats_.record_incremental_update();
  }

  // Handle a room visibility change
  void handle_room_visibility_change(const std::string& room_id,
                                      UserDirectoryRoomIsolator::RoomVisibility vis) {
    isolator_.set_room_visibility(room_id, vis);

    if (isolator_.should_exclude_from_directory(room_id)) {
      // Remove all users in this room from public view
      auto users_in_room = shared_tracker_.get_room_users(room_id);
      for (const auto& user_id : users_in_room) {
        auto existing = index_.get_entry(user_id);
        if (existing.has_value()) {
          existing->shared_rooms = shared_tracker_.get_user_rooms(user_id).size();
          cache_.put(user_id, existing.value());
        }
      }
    }
    stats_.record_incremental_update();
  }

  // Handle user deactivation
  void handle_deactivation(const std::string& user_id,
                           const std::string& reason = "") {
    deactivation_handler_.deactivate_user(user_id, reason);
    index_.remove_user(user_id);
    cache_.remove(user_id);
    shared_tracker_.remove_user(user_id);
    stats_.record_incremental_update();
  }

  // Handle user reactivation
  void handle_reactivation(const std::string& user_id) {
    deactivation_handler_.reactivate_user(user_id);
    stats_.record_incremental_update();
  }

  // Handle room creation
  void handle_room_creation(const std::string& room_id,
                             UserDirectoryRoomIsolator::RoomVisibility vis) {
    isolator_.set_room_visibility(room_id, vis);
    stats_.record_incremental_update();
  }

  // Process a batch of events
  enum class EventType {
    PROFILE_CHANGE,
    ROOM_JOIN,
    ROOM_LEAVE,
    ROOM_VISIBILITY_CHANGE,
    USER_DEACTIVATE,
    USER_REACTIVATE,
    ROOM_CREATE
  };

  struct DirectoryEvent {
    EventType type;
    std::string user_id;
    std::string room_id;
    std::string display_name;
    std::optional<std::string> avatar_url;
    std::string reason;
    UserDirectoryRoomIsolator::RoomVisibility visibility{
        UserDirectoryRoomIsolator::RoomVisibility::PUBLIC};
  };

  void process_event(const DirectoryEvent& event) {
    switch (event.type) {
      case EventType::PROFILE_CHANGE:
        handle_profile_change(event.user_id, event.display_name,
                               event.avatar_url);
        break;
      case EventType::ROOM_JOIN:
        handle_room_join(event.user_id, event.room_id);
        break;
      case EventType::ROOM_LEAVE:
        handle_room_leave(event.user_id, event.room_id);
        break;
      case EventType::ROOM_VISIBILITY_CHANGE:
        handle_room_visibility_change(event.room_id, event.visibility);
        break;
      case EventType::USER_DEACTIVATE:
        handle_deactivation(event.user_id, event.reason);
        break;
      case EventType::USER_REACTIVATE:
        handle_reactivation(event.user_id);
        break;
      case EventType::ROOM_CREATE:
        handle_room_creation(event.room_id, event.visibility);
        break;
    }
  }

  void process_events(const std::vector<DirectoryEvent>& events) {
    for (const auto& event : events) {
      process_event(event);
    }
  }

  // Handle bulk room join (e.g., initial sync)
  void handle_bulk_room_join(const std::string& user_id,
                              const std::vector<std::string>& room_ids) {
    for (const auto& room_id : room_ids) {
      handle_room_join(user_id, room_id);
    }
  }

  // Handle bulk profile update
  void handle_bulk_profile_update(
      const std::vector<std::tuple<std::string, std::string,
                                    std::optional<std::string>>>& updates) {
    for (const auto& [uid, name, avatar] : updates) {
      handle_profile_change(uid, name, avatar);
    }
  }

private:
  UserDirectorySearchIndex& index_;
  SharedRoomsTracker& shared_tracker_;
  UserDirectoryDeactivationHandler& deactivation_handler_;
  UserDirectoryRoomIsolator& isolator_;
  UserDirectoryCacheManager& cache_;
  UserDirectoryStatsCollector& stats_;
};

// ============================================================================
// UserDirectorySearchEngine - Main search engine for user directory
// ============================================================================
class UserDirectorySearchEngine {
public:
  UserDirectorySearchEngine(
      UserDirectorySearchIndex& index,
      SharedRoomsTracker& shared_tracker,
      UserDirectoryDeactivationHandler& deactivation_handler,
      UserDirectoryRoomIsolator& isolator,
      UserDirectoryProfileRanker& ranker,
      UserDirectoryCacheManager& cache,
      UserDirectoryStatsCollector& stats)
      : index_(index),
        shared_tracker_(shared_tracker),
        deactivation_handler_(deactivation_handler),
        isolator_(isolator),
        ranker_(ranker),
        cache_(cache),
        stats_(stats) {}

  // Search user directory by display name or user ID
  std::vector<UserDirectorySearchResult> search_users(
      const UserDirectorySearchQuery& query) {

    auto start = chr::steady_clock::now();

    std::vector<UserDirectorySearchResult> results;

    // Try cache for exact searches
    if (query.exact_match && query.requester_id.has_value()) {
      std::string cache_key = "search:" + to_lower(query.search_term) +
                              ":" + query.requester_id.value();
      auto cached = search_cache_.get(cache_key);
      if (cached.has_value()) {
        stats_.record_cache_hit();
        auto elapsed = chr::duration_cast<chr::milliseconds>(
                           chr::steady_clock::now() - start)
                           .count();
        stats_.record_search(elapsed);
        return cached.value();
      }
      stats_.record_cache_miss();
    }

    // Perform search
    auto entries = index_.search(query);

    for (auto& entry : entries) {
      // Filter deactivated users if requested
      if (!query.include_deactivated &&
          deactivation_handler_.is_deactivated(entry.user_id))
        continue;

      // Per-room isolation check
      if (query.requester_id.has_value()) {
        bool can_see = isolator_.can_see_user(query.requester_id.value(),
                                               entry.user_id, shared_tracker_);
        if (!can_see) continue;

        // Get visible shared rooms
        auto visible_rooms = isolator_.get_visible_shared_rooms(
            query.requester_id.value(), entry.user_id, shared_tracker_);
        entry.shared_rooms = visible_rooms.size();
      } else {
        entry.shared_rooms = shared_tracker_.get_user_rooms(entry.user_id).size();
      }

      UserDirectorySearchResult result;
      result.entry = entry;
      results.push_back(result);
    }

    // Rank results
    ranker_.rank(results, query, shared_tracker_);

    // Apply offset and limit
    if (query.offset > 0 && query.offset < static_cast<int>(results.size())) {
      results.erase(results.begin(), results.begin() + query.offset);
    }
    if (query.limit > 0 && query.limit < static_cast<int>(results.size())) {
      results.resize(query.limit);
    }

    // Cache exact searches
    if (query.exact_match && query.requester_id.has_value() &&
        results.size() <= 20) {
      std::string cache_key = "search:" + to_lower(query.search_term) +
                              ":" + query.requester_id.value();
      search_cache_.put(cache_key, results, chr::minutes(5));
    }

    auto elapsed = chr::duration_cast<chr::milliseconds>(
                       chr::steady_clock::now() - start)
                       .count();
    stats_.record_search(elapsed);
    return results;
  }

  // Search across all public rooms for users (profile search)
  std::vector<UserDirectorySearchResult> search_all_public_rooms(
      const std::string& search_term,
      int limit = 10,
      const std::optional<std::string>& requester_id = std::nullopt) {

    UserDirectorySearchQuery query;
    query.search_term = search_term;
    query.limit = limit;
    query.requester_id = requester_id;
    query.order_by = "shared_rooms";
    query.ascending = false;
    return search_users(query);
  }

  // Search users in a specific room
  std::vector<UserDirectorySearchResult> search_users_in_room(
      const std::string& room_id,
      const UserDirectorySearchQuery& query) {

    auto room_users = shared_tracker_.get_room_users(room_id);
    std::vector<UserDirectorySearchResult> results;

    for (const auto& user_id : room_users) {
      auto entry = index_.get_entry(user_id);
      if (!entry.has_value()) continue;
      if (!query.include_deactivated && entry->deactivated) continue;

      if (!fuzzy_match(entry->display_name, query.search_term) &&
          !fuzzy_match(entry->user_id, query.search_term))
        continue;

      UserDirectorySearchResult result;
      result.entry = entry.value();
      result.shared_room_count = 1;  // At minimum, this room
      results.push_back(result);
    }

    ranker_.rank(results, query, shared_tracker_);

    if (query.offset > 0 && query.offset < static_cast<int>(results.size()))
      results.erase(results.begin(), results.begin() + query.offset);
    if (query.limit > 0 && query.limit < static_cast<int>(results.size()))
      results.resize(query.limit);

    return results;
  }

  // Get all users a requester can see (paginated)
  std::vector<UserDirectorySearchResult> browse_directory(
      const std::optional<std::string>& requester_id,
      int limit = 50,
      int offset = 0) {

    auto all_ids = index_.get_all_user_ids();
    std::vector<UserDirectorySearchResult> results;

    for (const auto& user_id : all_ids) {
      if (deactivation_handler_.is_deactivated(user_id)) continue;

      if (requester_id.has_value()) {
        bool can_see = isolator_.can_see_user(requester_id.value(),
                                               user_id, shared_tracker_);
        if (!can_see) continue;
      }

      auto entry = index_.get_entry(user_id);
      if (!entry.has_value()) continue;

      UserDirectorySearchResult result;
      result.entry = entry.value();
      if (requester_id.has_value()) {
        result.shared_room_count = shared_tracker_.count_shared_rooms(
            requester_id.value(), user_id);
      } else {
        result.shared_room_count =
            shared_tracker_.get_user_rooms(user_id).size();
      }
      results.push_back(result);
    }

    // Sort by shared rooms descending
    std::sort(results.begin(), results.end(),
              [](const UserDirectorySearchResult& a,
                 const UserDirectorySearchResult& b) {
                if (a.shared_room_count != b.shared_room_count)
                  return a.shared_room_count > b.shared_room_count;
                return a.entry.display_name < b.entry.display_name;
              });

    if (offset > 0 && offset < static_cast<int>(results.size()))
      results.erase(results.begin(), results.begin() + offset);
    if (limit > 0 && limit < static_cast<int>(results.size()))
      results.resize(limit);

    return results;
  }

  // Lookup a specific user in the directory
  std::optional<UserDirectorySearchResult> lookup_user(
      const std::string& user_id,
      const std::optional<std::string>& requester_id = std::nullopt) {

    stats_.record_lookup();

    // Check cache
    auto cached = lookup_cache_.get("lookup:" + user_id);
    if (cached.has_value()) {
      stats_.record_cache_hit();
      return cached.value();
    }
    stats_.record_cache_miss();

    auto entry = index_.get_entry(user_id);
    if (!entry.has_value()) return std::nullopt;

    if (deactivation_handler_.is_deactivated(user_id)) return std::nullopt;

    if (requester_id.has_value()) {
      bool can_see = isolator_.can_see_user(requester_id.value(), user_id,
                                             shared_tracker_);
      if (!can_see) return std::nullopt;
    }

    UserDirectorySearchResult result;
    result.entry = entry.value();
    if (requester_id.has_value()) {
      result.shared_room_count = shared_tracker_.count_shared_rooms(
          requester_id.value(), user_id);
    } else {
      result.shared_room_count =
          shared_tracker_.get_user_rooms(user_id).size();
    }

    lookup_cache_.put("lookup:" + user_id, result, chr::minutes(10));
    return result;
  }

  // Autocomplete / typeahead search
  std::vector<UserDirectorySearchResult> autocomplete(
      const std::string& prefix,
      int limit = 5,
      const std::optional<std::string>& requester_id = std::nullopt) {

    UserDirectorySearchQuery query;
    query.search_term = prefix;
    query.limit = limit;
    query.requester_id = requester_id;
    return search_users(query);
  }

  // Invalidate caches
  void invalidate_caches() {
    search_cache_.invalidate();
    lookup_cache_.invalidate();
  }

private:
  UserDirectorySearchIndex& index_;
  SharedRoomsTracker& shared_tracker_;
  UserDirectoryDeactivationHandler& deactivation_handler_;
  UserDirectoryRoomIsolator& isolator_;
  UserDirectoryProfileRanker& ranker_;
  UserDirectoryCacheManager& cache_;
  UserDirectoryStatsCollector& stats_;

  // Time-based cache for search results
  struct TimedCache {
    struct TimedEntry {
      std::vector<UserDirectorySearchResult> results;
      chr::steady_clock::time_point expiry;
    };

    void put(const std::string& key,
             const std::vector<UserDirectorySearchResult>& results,
             chr::minutes ttl) {
      std::lock_guard<std::mutex> lock(mutex_);
      TimedEntry te;
      te.results = results;
      te.expiry = chr::steady_clock::now() + ttl;
      cache_[key] = te;
    }

    std::optional<std::vector<UserDirectorySearchResult>> get(
        const std::string& key) {
      std::lock_guard<std::mutex> lock(mutex_);
      auto it = cache_.find(key);
      if (it == cache_.end()) return std::nullopt;
      if (chr::steady_clock::now() > it->second.expiry) {
        cache_.erase(it);
        return std::nullopt;
      }
      return it->second.results;
    }

    void invalidate() {
      std::lock_guard<std::mutex> lock(mutex_);
      cache_.clear();
    }

  private:
    std::mutex mutex_;
    std::unordered_map<std::string, TimedEntry> cache_;
  };

  TimedCache search_cache_;

  // Time-based cache for individual lookups
  struct SingleTimedCache {
    struct TimedEntry {
      UserDirectorySearchResult result;
      chr::steady_clock::time_point expiry;
    };

    void put(const std::string& key,
             const UserDirectorySearchResult& result,
             chr::minutes ttl) {
      std::lock_guard<std::mutex> lock(mutex_);
      TimedEntry te;
      te.result = result;
      te.expiry = chr::steady_clock::now() + ttl;
      cache_[key] = te;
    }

    std::optional<UserDirectorySearchResult> get(const std::string& key) {
      std::lock_guard<std::mutex> lock(mutex_);
      auto it = cache_.find(key);
      if (it == cache_.end()) return std::nullopt;
      if (chr::steady_clock::now() > it->second.expiry) {
        cache_.erase(it);
        return std::nullopt;
      }
      return it->second.result;
    }

    void invalidate() {
      std::lock_guard<std::mutex> lock(mutex_);
      cache_.clear();
    }

  private:
    std::mutex mutex_;
    std::unordered_map<std::string, TimedEntry> cache_;
  };

  SingleTimedCache lookup_cache_;
};

// ============================================================================
// UserDirectoryManager - Main coordinator for user directory operations
// Equivalent to synapse/handlers/user_directory.py
// ============================================================================
class UserDirectoryManager {
public:
  UserDirectoryManager()
      : index_(),
        shared_tracker_(),
        deactivation_handler_(),
        isolator_(),
        cache_(10000),
        stats_(),
        ranker_(),
        rebuilder_(index_, shared_tracker_, deactivation_handler_, isolator_,
                    stats_, cache_),
        updater_(index_, shared_tracker_, deactivation_handler_, isolator_,
                  cache_, stats_),
        search_engine_(index_, shared_tracker_, deactivation_handler_,
                        isolator_, ranker_, cache_, stats_),
        batch_processor_() {}

  // ---- User Directory CRUD ----

  // Add a user to the directory
  void add_user(const std::string& user_id,
                const std::string& display_name,
                const std::optional<std::string>& avatar_url = std::nullopt) {
    if (!is_valid_user_id(user_id)) {
      throw std::invalid_argument("Invalid user ID: " + user_id);
    }

    UserDirectoryEntry entry;
    entry.user_id = user_id;
    entry.display_name = display_name;
    entry.avatar_url = avatar_url;
    entry.created_ts = current_time_ms();
    entry.last_updated_ts = current_time_ms();
    entry.deactivated = false;

    index_.index_user(entry);
    cache_.put(user_id, entry);
    stats_.record_incremental_update();
  }

  // Remove a user from the directory
  void remove_user(const std::string& user_id) {
    index_.remove_user(user_id);
    cache_.remove(user_id);
    shared_tracker_.remove_user(user_id);
    search_engine_.invalidate_caches();
    stats_.record_incremental_update();
  }

  // Update a user's profile in the directory
  void update_user_profile(const std::string& user_id,
                            const std::string& display_name,
                            const std::optional<std::string>& avatar_url) {
    updater_.handle_profile_change(user_id, display_name, avatar_url);
    search_engine_.invalidate_caches();
  }

  // Get a user entry from the directory
  std::optional<UserDirectoryEntry> get_user(const std::string& user_id) {
    // Check cache first
    auto cached = cache_.get(user_id);
    if (cached.has_value()) {
      stats_.record_cache_hit();
      return cached;
    }
    stats_.record_cache_miss();

    auto entry = index_.get_entry(user_id);
    if (entry.has_value()) {
      cache_.put(user_id, entry.value());
    }
    return entry;
  }

  // Check if a user is in the directory
  bool has_user(const std::string& user_id) {
    return index_.get_entry(user_id).has_value() &&
           !deactivation_handler_.is_deactivated(user_id);
  }

  // ---- User Deactivation ----

  // Deactivate a user (remove from directory)
  void deactivate_user(const std::string& user_id,
                        const std::string& reason = "") {
    updater_.handle_deactivation(user_id, reason);
    search_engine_.invalidate_caches();
  }

  // Reactivate a previously deactivated user
  void reactivate_user(const std::string& user_id) {
    updater_.handle_reactivation(user_id);
  }

  // Check if user is deactivated
  bool is_deactivated(const std::string& user_id) const {
    return deactivation_handler_.is_deactivated(user_id);
  }

  // ---- Room Membership Handlers ----

  // Handle user joining a room
  void handle_room_join(const std::string& user_id,
                        const std::string& room_id) {
    updater_.handle_room_join(user_id, room_id);
  }

  // Handle user leaving a room
  void handle_room_leave(const std::string& user_id,
                         const std::string& room_id) {
    updater_.handle_room_leave(user_id, room_id);
  }

  // Handle room visibility change
  void set_room_visibility(
      const std::string& room_id,
      UserDirectoryRoomIsolator::RoomVisibility visibility) {
    updater_.handle_room_visibility_change(room_id, visibility);
  }

  // Handle room creation
  void handle_room_creation(
      const std::string& room_id,
      UserDirectoryRoomIsolator::RoomVisibility visibility =
          UserDirectoryRoomIsolator::RoomVisibility::PUBLIC) {
    updater_.handle_room_creation(room_id, visibility);
  }

  // ---- Searching ----

  // Search user directory
  std::vector<UserDirectorySearchResult> search(
      const UserDirectorySearchQuery& query) {
    return search_engine_.search_users(query);
  }

  // Simple search by term
  std::vector<UserDirectorySearchResult> search_by_term(
      const std::string& term,
      int limit = 10,
      const std::optional<std::string>& requester_id = std::nullopt) {
    UserDirectorySearchQuery query = UserDirectorySearchQuery::create(term, limit);
    query.requester_id = requester_id;
    return search(query);
  }

  // Search by display name
  std::vector<UserDirectorySearchResult> search_by_display_name(
      const std::string& display_name,
      int limit = 10,
      const std::optional<std::string>& requester_id = std::nullopt) {
    UserDirectorySearchQuery query = UserDirectorySearchQuery::create(display_name, limit);
    query.requester_id = requester_id;
    return search(query);
  }

  // Search by user ID (exact or prefix)
  std::vector<UserDirectorySearchResult> search_by_user_id(
      const std::string& user_id_pattern,
      int limit = 10,
      const std::optional<std::string>& requester_id = std::nullopt) {
    UserDirectorySearchQuery query = UserDirectorySearchQuery::create(user_id_pattern, limit);
    query.search_by_userid = true;
    query.requester_id = requester_id;
    return search(query);
  }

  // Profile search: search across all public rooms
  std::vector<UserDirectorySearchResult> search_all_public_rooms(
      const std::string& term,
      int limit = 10,
      const std::optional<std::string>& requester_id = std::nullopt) {
    return search_engine_.search_all_public_rooms(term, limit, requester_id);
  }

  // Autocomplete / typeahead
  std::vector<UserDirectorySearchResult> autocomplete(
      const std::string& prefix,
      int limit = 5,
      const std::optional<std::string>& requester_id = std::nullopt) {
    return search_engine_.autocomplete(prefix, limit, requester_id);
  }

  // Browse the directory (paginated)
  std::vector<UserDirectorySearchResult> browse(
      int limit = 50,
      int offset = 0,
      const std::optional<std::string>& requester_id = std::nullopt) {
    return search_engine_.browse_directory(requester_id, limit, offset);
  }

  // Lookup a specific user
  std::optional<UserDirectorySearchResult> lookup(
      const std::string& user_id,
      const std::optional<std::string>& requester_id = std::nullopt) {
    return search_engine_.lookup_user(user_id, requester_id);
  }

  // ---- Directory Rebuild ----

  // Full rebuild from provided data
  void rebuild(
      const std::vector<UserDirectoryEntry>& users,
      const std::vector<std::pair<std::string, std::string>>& memberships,
      const UserDirectoryRebuilder::RebuildConfig& config = {}) {
    rebuilder_.rebuild(users, memberships, config);
    search_engine_.invalidate_caches();
  }

  // Get rebuild progress
  UserDirectoryRebuilder::RebuildProgress get_rebuild_progress() const {
    return rebuilder_.get_last_progress();
  }

  // ---- Batch Operations ----

  // Enqueue a batch operation
  void enqueue_batch(const UserDirectoryBatchProcessor::BatchOperation& op) {
    batch_processor_.enqueue(op);
  }

  // Enqueue multiple operations
  void enqueue_batch_bulk(
      const std::vector<UserDirectoryBatchProcessor::BatchOperation>& ops) {
    batch_processor_.enqueue_bulk(ops);
  }

  // Process all pending batch operations
  void process_batch() {
    auto ops = batch_processor_.dequeue_all();
    for (const auto& op : ops) {
      switch (op.type) {
        case UserDirectoryBatchProcessor::BatchOperation::ADD:
          add_user(op.user_id, op.display_name, op.avatar_url);
          break;
        case UserDirectoryBatchProcessor::BatchOperation::UPDATE:
          update_user_profile(op.user_id, op.display_name, op.avatar_url);
          break;
        case UserDirectoryBatchProcessor::BatchOperation::REMOVE:
          remove_user(op.user_id);
          break;
        case UserDirectoryBatchProcessor::BatchOperation::DEACTIVATE:
          deactivate_user(op.user_id);
          break;
        case UserDirectoryBatchProcessor::BatchOperation::REACTIVATE:
          reactivate_user(op.user_id);
          break;
      }
    }
    search_engine_.invalidate_caches();
  }

  size_t pending_batch_operations() const {
    return batch_processor_.pending();
  }

  // ---- Room Member Sync ----

  // Sync a user's room memberships (full refresh)
  void sync_user_rooms(const std::string& user_id,
                       const std::vector<std::string>& room_ids) {
    updater_.handle_bulk_room_join(user_id, room_ids);
    search_engine_.invalidate_caches();
  }

  // Sync users in a room (full refresh for the room)
  void sync_room_users(const std::string& room_id,
                       const std::vector<std::string>& user_ids,
                       const std::vector<UserDirectoryEntry>& entries) {
    rebuilder_.rebuild_room_users(room_id, user_ids, entries);
    search_engine_.invalidate_caches();
  }

  // ---- Statistics ----

  // Get directory stats
  UserDirectoryStatsCollector::DirectoryStats get_stats() const {
    return stats_.get_stats();
  }

  // Get stats as JSON
  json get_stats_json() const {
    return stats_.get_stats_json();
  }

  // Get total user count
  size_t user_count() const {
    return index_.size();
  }

  // Get total room count
  size_t room_count() const {
    return shared_tracker_.total_rooms();
  }

  // ---- Access to sub-components (for advanced usage) ----
  UserDirectorySearchIndex& search_index() { return index_; }
  SharedRoomsTracker& shared_rooms() { return shared_tracker_; }
  UserDirectoryDeactivationHandler& deactivation() { return deactivation_handler_; }
  UserDirectoryRoomIsolator& isolator() { return isolator_; }
  UserDirectoryCacheManager& cache() { return cache_; }
  UserDirectoryStatsCollector& stats_collector() { return stats_; }
  UserDirectoryIncrementalUpdater& incremental_updater() { return updater_; }
  UserDirectorySearchEngine& search_engine() { return search_engine_; }

private:
  UserDirectorySearchIndex index_;
  SharedRoomsTracker shared_tracker_;
  UserDirectoryDeactivationHandler deactivation_handler_;
  UserDirectoryRoomIsolator isolator_;
  UserDirectoryCacheManager cache_;
  UserDirectoryStatsCollector stats_;
  UserDirectoryProfileRanker ranker_;
  UserDirectoryRebuilder rebuilder_;
  UserDirectoryIncrementalUpdater updater_;
  UserDirectorySearchEngine search_engine_;
  UserDirectoryBatchProcessor batch_processor_;
};

// ============================================================================
// UserDirectoryAPI - Public API for user directory operations
// This is the main interface consumed by the REST layer
// ============================================================================
class UserDirectoryAPI {
public:
  UserDirectoryAPI() : manager_(std::make_shared<UserDirectoryManager>()) {}

  explicit UserDirectoryAPI(std::shared_ptr<UserDirectoryManager> manager)
      : manager_(std::move(manager)) {}

  // ---- User Directory API Methods (Matrix Spec) ----

  // POST /_matrix/client/v3/user_directory/search
  // Search the user directory
  json search_users(const json& request_body) {
    std::string search_term = request_body.value("search_term", "");
    int limit = request_body.value("limit", 10);

    UserDirectorySearchQuery query = UserDirectorySearchQuery::create(search_term, limit);

    // Support Matrix spec limit (capped at 50 for client API)
    if (limit < 1) limit = 1;
    if (limit > 50) limit = 50;
    query.limit = limit;

    auto results = manager_->search(query);

    json response;
    response["results"] = json::array();
    for (const auto& result : results) {
      response["results"].push_back(result.to_json());
    }
    response["limited"] = false;  // Could be true if results exceed limit

    return response;
  }

  // Search the user directory with a requester context
  json search_users_as(const std::string& requester_id,
                        const json& request_body) {
    std::string search_term = request_body.value("search_term", "");
    int limit = request_body.value("limit", 10);

    UserDirectorySearchQuery query = UserDirectorySearchQuery::create(search_term, limit);
    query.requester_id = requester_id;
    if (limit < 1) limit = 1;
    if (limit > 50) limit = 50;
    query.limit = limit;

    auto results = manager_->search(query);

    json response;
    response["results"] = json::array();
    for (const auto& result : results) {
      response["results"].push_back(result.to_json());
    }
    response["limited"] = false;

    return response;
  }

  // Admin endpoint: add user to directory
  json admin_add_user(const std::string& user_id,
                       const std::string& display_name,
                       const std::optional<std::string>& avatar_url = std::nullopt) {
    manager_->add_user(user_id, display_name, avatar_url);
    json response;
    response["status"] = "ok";
    response["user_id"] = user_id;
    return response;
  }

  // Admin endpoint: remove user from directory
  json admin_remove_user(const std::string& user_id) {
    manager_->remove_user(user_id);
    json response;
    response["status"] = "ok";
    response["user_id"] = user_id;
    return response;
  }

  // Admin endpoint: deactivate user
  json admin_deactivate_user(const std::string& user_id,
                              const std::string& reason = "") {
    manager_->deactivate_user(user_id, reason);
    json response;
    response["status"] = "ok";
    response["user_id"] = user_id;
    response["deactivated"] = true;
    if (!reason.empty()) response["reason"] = reason;
    return response;
  }

  // Admin endpoint: reactivate user
  json admin_reactivate_user(const std::string& user_id) {
    manager_->reactivate_user(user_id);
    json response;
    response["status"] = "ok";
    response["user_id"] = user_id;
    response["reactivated"] = true;
    return response;
  }

  // Admin endpoint: rebuild directory
  json admin_rebuild_directory(
      const std::vector<UserDirectoryEntry>& users,
      const std::vector<std::pair<std::string, std::string>>& memberships) {
    manager_->rebuild(users, memberships);

    json response;
    auto progress = manager_->get_rebuild_progress();
    response["status"] = "ok";
    response["total_users"] = progress.total_users;
    response["processed_users"] = progress.processed_users;
    response["total_rooms"] = progress.total_rooms;
    response["processed_rooms"] = progress.processed_rooms;
    response["complete"] = progress.complete;
    return response;
  }

  // Admin endpoint: directory statistics
  json admin_get_stats() {
    return manager_->get_stats_json();
  }

  // Admin endpoint: set room visibility
  json admin_set_room_visibility(
      const std::string& room_id,
      const std::string& visibility) {
    auto vis = UserDirectoryRoomIsolator::string_to_visibility(visibility);
    manager_->set_room_visibility(room_id, vis);

    json response;
    response["status"] = "ok";
    response["room_id"] = room_id;
    response["visibility"] = visibility;
    return response;
  }

  // Admin endpoint: get room visibility
  json admin_get_room_visibility(const std::string& room_id) {
    auto vis = manager_->isolator().get_room_visibility(room_id);
    json response;
    response["room_id"] = room_id;
    response["visibility"] = UserDirectoryRoomIsolator::visibility_to_string(vis);
    return response;
  }

  // Admin endpoint: get deactivated users
  json admin_get_deactivated_users() {
    auto deactivated = manager_->deactivation().get_all_deactivated_users();
    json response;
    response["users"] = json::array();
    for (const auto& rec : deactivated) {
      json u;
      u["user_id"] = rec.user_id;
      u["deactivated_at"] = rec.deactivated_at;
      u["reason"] = rec.reason;
      response["users"].push_back(u);
    }
    response["total"] = deactivated.size();
    return response;
  }

  // Admin endpoint: process batch operations
  json admin_process_batch(
      const std::vector<UserDirectoryBatchProcessor::BatchOperation>& ops) {
    manager_->enqueue_batch_bulk(ops);
    manager_->process_batch();

    json response;
    response["status"] = "ok";
    response["processed"] = ops.size();
    response["pending"] = manager_->pending_batch_operations();
    return response;
  }

  // ---- Event Handlers (for integration with event processing pipeline) ----

  // Handle a profile change event
  void on_profile_change(const std::string& user_id,
                          const std::string& display_name,
                          const std::optional<std::string>& avatar_url) {
    manager_->update_user_profile(user_id, display_name, avatar_url);
  }

  // Handle a room membership change event
  void on_room_membership_change(const std::string& user_id,
                                  const std::string& room_id,
                                  const std::string& membership,
                                  const std::string& prev_membership) {
    if (membership == "join") {
      manager_->handle_room_join(user_id, room_id);
    } else if (membership == "leave" || membership == "ban") {
      manager_->handle_room_leave(user_id, room_id);
    }
    (void)prev_membership;
  }

  // Handle a room creation event
  void on_room_create(const std::string& room_id, bool is_public) {
    auto vis = is_public
                   ? UserDirectoryRoomIsolator::RoomVisibility::PUBLIC
                   : UserDirectoryRoomIsolator::RoomVisibility::SHARED_ONLY;
    manager_->handle_room_creation(room_id, vis);
  }

  // Handle a user deactivation event
  void on_user_deactivate(const std::string& user_id,
                          const std::string& reason = "") {
    manager_->deactivate_user(user_id, reason);
  }

  // Handle a user reactivation event
  void on_user_reactivate(const std::string& user_id) {
    manager_->reactivate_user(user_id);
  }

  // ---- Convenience methods for the REST layer ----

  // Quick search (simplified interface)
  json quick_search(const std::string& term, int limit = 10) {
    json body;
    body["search_term"] = term;
    body["limit"] = limit;
    return search_users(body);
  }

  // Quick search as a user
  json quick_search_as(const std::string& requester, const std::string& term,
                        int limit = 10) {
    json body;
    body["search_term"] = term;
    body["limit"] = limit;
    return search_users_as(requester, body);
  }

  // Get underlying manager
  std::shared_ptr<UserDirectoryManager> manager() { return manager_; }

private:
  std::shared_ptr<UserDirectoryManager> manager_;
};

// ============================================================================
// UserDirectoryBackgroundWorker - Background maintenance worker
// ============================================================================
class UserDirectoryBackgroundWorker {
public:
  UserDirectoryBackgroundWorker(
      std::shared_ptr<UserDirectoryManager> manager,
      chr::seconds interval = chr::seconds(300))
      : manager_(std::move(manager)),
        interval_(interval),
        running_(false) {}

  ~UserDirectoryBackgroundWorker() { stop(); }

  void start() {
    if (running_.exchange(true)) return;
    worker_thread_ = std::thread([this]() { run(); });
  }

  void stop() {
    running_.store(false);
    if (worker_thread_.joinable()) {
      worker_thread_.join();
    }
  }

  // Set cleanup callbacks
  using CleanupCallback = std::function<void()>;
  void set_on_cleanup(CleanupCallback cb) { on_cleanup_ = std::move(cb); }

private:
  void run() {
    while (running_.load()) {
      auto start = chr::steady_clock::now();

      try {
        // Process pending batch operations
        manager_->process_batch();

        // Cleanup stale cache entries
        // (The cache itself handles LRU eviction, but we trigger a GC pass)
        manager_->search_engine().invalidate_caches();

        if (on_cleanup_) on_cleanup_();
      } catch (const std::exception& e) {
        std::cerr << "[UserDirectory] Background worker error: " << e.what()
                  << std::endl;
      }

      auto elapsed = chr::steady_clock::now() - start;
      auto remaining = interval_ - chr::duration_cast<chr::seconds>(elapsed);
      if (remaining > chr::seconds(0)) {
        std::this_thread::sleep_for(remaining);
      }
    }
  }

  std::shared_ptr<UserDirectoryManager> manager_;
  chr::seconds interval_;
  std::atomic<bool> running_;
  std::thread worker_thread_;
  CleanupCallback on_cleanup_;
};

// ============================================================================
// UserDirectoryExportHelper - JSON export/import for directory data
// ============================================================================
class UserDirectoryExportHelper {
public:
  // Export the full directory as JSON
  static json export_directory(UserDirectoryManager& manager) {
    json doc;
    doc["version"] = 1;
    doc["exported_at"] = current_iso8601();

    // Export users
    doc["users"] = json::array();
    auto all_ids = manager.search_index().get_all_user_ids();
    for (const auto& user_id : all_ids) {
      auto entry = manager.search_index().get_entry(user_id);
      if (entry.has_value()) {
        json u;
        u["user_id"] = entry->user_id;
        u["display_name"] = entry->display_name;
        if (entry->avatar_url.has_value())
          u["avatar_url"] = entry->avatar_url.value();
        u["deactivated"] = entry->deactivated;
        u["shared_rooms"] = entry->shared_rooms;
        u["created_ts"] = entry->created_ts;
        u["last_updated_ts"] = entry->last_updated_ts;
        doc["users"].push_back(u);
      }
    }

    // Export deactivated users
    doc["deactivated_users"] = json::array();
    auto deactivated = manager.deactivation().get_all_deactivated_users();
    for (const auto& rec : deactivated) {
      json d;
      d["user_id"] = rec.user_id;
      d["deactivated_at"] = rec.deactivated_at;
      d["reason"] = rec.reason;
      doc["deactivated_users"].push_back(d);
    }

    // Export stats
    doc["stats"] = manager.get_stats_json();

    return doc;
  }

  // Import directory from JSON
  static void import_directory(UserDirectoryManager& manager,
                                const json& doc) {
    std::vector<UserDirectoryEntry> entries;
    if (doc.contains("users") && doc["users"].is_array()) {
      for (const auto& u : doc["users"]) {
        UserDirectoryEntry entry;
        entry.user_id = u.value("user_id", "");
        entry.display_name = u.value("display_name", "");
        if (u.contains("avatar_url") && !u["avatar_url"].is_null())
          entry.avatar_url = u["avatar_url"].get<std::string>();
        entry.deactivated = u.value("deactivated", false);
        entry.shared_rooms = u.value("shared_rooms", int64_t{0});
        entry.created_ts = u.value("created_ts", int64_t{0});
        entry.last_updated_ts = u.value("last_updated_ts", int64_t{0});
        entries.push_back(entry);
      }
    }

    std::vector<std::pair<std::string, std::string>> memberships;
    // Memberships are reconstructed from shared_rooms data
    // In a full import, room memberships would be provided separately

    manager.rebuild(entries, memberships);

    // Import deactivated users
    if (doc.contains("deactivated_users") && doc["deactivated_users"].is_array()) {
      for (const auto& d : doc["deactivated_users"]) {
        std::string uid = d.value("user_id", "");
        std::string reason = d.value("reason", "");
        manager.deactivate_user(uid, reason);
      }
    }
  }
};

// ============================================================================
// Global singleton accessor
// ============================================================================
namespace {

std::shared_ptr<UserDirectoryManager> g_user_directory_manager;
std::mutex g_user_directory_mutex;

} // anonymous namespace

std::shared_ptr<UserDirectoryManager> get_user_directory_manager() {
  std::lock_guard<std::mutex> lock(g_user_directory_mutex);
  if (!g_user_directory_manager) {
    g_user_directory_manager = std::make_shared<UserDirectoryManager>();
  }
  return g_user_directory_manager;
}

void set_user_directory_manager(std::shared_ptr<UserDirectoryManager> manager) {
  std::lock_guard<std::mutex> lock(g_user_directory_mutex);
  g_user_directory_manager = std::move(manager);
}

} // namespace progressive
