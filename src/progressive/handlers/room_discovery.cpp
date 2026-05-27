// room_discovery.cpp - Matrix Room Discovery Handlers
// Implements room preview, public room listing, room discovery API, 
// room directory, room alias management, third-party protocol rooms,
// room visibility, space discovery, room statistics, federation discovery.
//
// Based on Synapse: synapse/handlers/room_member.py, synapse/handlers/directory.py,
// synapse/handlers/room.py, synapse/handlers/space_summary.py
//
// Features:
//   1.  Public room listing API (GET /publicRooms)
//   2.  Public room search (POST /publicRooms with filter/search_term)
//   3.  Room preview for non-members (GET /rooms/{roomId}/preview)
//   4.  Room preview for unauthenticated users
//   5.  Room discovery via alias (GET /directory/room/{alias})
//   6.  Room directory management (PUT/DELETE /directory/room/{alias})
//   7.  Third-party protocol room listing
//   8.  Third-party protocol user/location queries
//   9.  Room canonical alias management (m.room.canonical_alias)
//  10.  Room alt aliases management
//  11.  Room visibility management (public/private)
//  12.  Room publishing to directory
//  13.  Room unpublishing from directory
//  14.  Room summary for unauthenticated users
//  15.  Space room discovery / space hierarchy traversal
//  16.  Room version discovery
//  17.  Federation room discovery (GET /_matrix/federation/v1/publicRooms)
//  18.  Room statistics for directory (totals, categories)
//  19.  Room directory pagination (since/limit, next_batch/prev_batch)
//  20.  Room directory filtering (by server, by network, by room_type)
//  21.  Room directory ordering (by member count, by name, by recency)
//  22.  Room search with full-text and filter support
//  23.  Room directory visibility checks
//  24.  Federated room discovery relay
//  25.  Room alias resolution with server list
//
// Target: 3500+ lines

#include "../json.hpp"
#include "progressive/storage/database.hpp"
#include "progressive/storage/databases/main/events.hpp"
#include "progressive/storage/databases/main/room.hpp"
#include "progressive/storage/databases/main/roommember.hpp"
#include "progressive/storage/databases/main/state.hpp"
#include "progressive/storage/databases/main/directory.hpp"
#include "progressive/storage/databases/main/profile.hpp"
#include "progressive/storage/databases/main/stream.hpp"
#include "progressive/storage/databases/main/event_federation.hpp"
#include "progressive/storage/databases/main/registration.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <random>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace progressive::handlers {

using json = nlohmann::json;
using namespace storage;

// ============================================================================
// Utility helpers
// ============================================================================

static std::atomic<int64_t> g_discovery_seq{1};
static std::mutex g_discovery_lock;

static int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();
}

static std::string gen_id(const std::string& prefix) {
  return prefix + std::to_string(now_ms()) + "-" +
         std::to_string(g_discovery_seq.fetch_add(1));
}

static std::string gen_token(int len = 32) {
  static const char cs[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  static thread_local std::mt19937 rng(
    static_cast<unsigned>(now_ms() + std::hash<std::thread::id>{}(std::this_thread::get_id())));
  std::uniform_int_distribution<> d(0, 61);
  std::string t(len, 'A');
  for (auto& c : t) c = cs[d(rng)];
  return t;
}

static std::string safe_str(const json& obj, const std::string& key,
                             const std::string& def = "") {
  if (!obj.contains(key)) return def;
  if (obj[key].is_string()) return obj[key].get<std::string>();
  return def;
}

static int64_t safe_int(const json& obj, const std::string& key,
                         int64_t def = 0) {
  if (!obj.contains(key)) return def;
  if (obj[key].is_number()) return obj[key].get<int64_t>();
  return def;
}

static bool safe_bool(const json& obj, const std::string& key, bool def = false) {
  if (!obj.contains(key)) return def;
  if (obj[key].is_boolean()) return obj[key].get<bool>();
  return def;
}

static std::string sql_escape(const std::string& s) {
  std::string out;
  out.reserve(s.size() + 4);
  for (char c : s) {
    if (c == '\'') out += "''";
    else out += c;
  }
  return out;
}

static std::string extract_localpart(const std::string& user_id) {
  if (user_id.empty() || user_id[0] != '@') return user_id;
  auto pos = user_id.find(':');
  if (pos == std::string::npos) return user_id.substr(1);
  return user_id.substr(1, pos - 1);
}

static std::string extract_domain(const std::string& mxid) {
  auto pos = mxid.find(':');
  if (pos == std::string::npos) return "";
  return mxid.substr(pos + 1);
}

static std::string extract_server_name(const std::string& room_alias) {
  auto pos = room_alias.find(':');
  if (pos == std::string::npos) return "";
  return room_alias.substr(pos + 1);
}

static bool validate_room_id(const std::string& room_id) {
  return room_id.size() >= 2 && room_id[0] == '!' &&
         room_id.find(':') != std::string::npos;
}

static bool validate_room_alias(const std::string& alias) {
  return alias.size() >= 2 && alias[0] == '#' &&
         alias.find(':') != std::string::npos;
}

static bool validate_user_id(const std::string& user_id) {
  return user_id.size() >= 4 && user_id[0] == '@' &&
         user_id.find(':') != std::string::npos;
}

static std::string normalize_search_term(const std::string& term) {
  std::string result;
  result.reserve(term.size());
  for (char c : term) {
    result += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return result;
}

static std::vector<std::string> tokenize_search(const std::string& term) {
  std::vector<std::string> tokens;
  std::istringstream iss(term);
  std::string token;
  while (iss >> token) {
    if (!token.empty()) {
      tokens.push_back(normalize_search_term(token));
    }
  }
  return tokens;
}

static bool matches_search(const std::string& name, const std::string& topic,
                           const std::string& canonical_alias,
                           const std::string& room_id,
                           const std::vector<std::string>& tokens) {
  if (tokens.empty()) return true;
  std::string haystack =
    normalize_search_term(name) + " " +
    normalize_search_term(topic) + " " +
    normalize_search_term(canonical_alias) + " " +
    normalize_search_term(room_id);
  for (const auto& t : tokens) {
    if (haystack.find(t) == std::string::npos) return false;
  }
  return true;
}

static std::string get_visibility_string(json& history_vis_event) {
  if (history_vis_event.empty()) return "shared";
  return safe_str(history_vis_event, "history_visibility", "shared");
}

// ============================================================================
// RoomDirectoryEntry - Data structure for a room in the directory
// ============================================================================

struct RoomDirectoryEntry {
  std::string room_id;
  std::string name;
  std::string topic;
  std::string avatar_url;
  std::string canonical_alias;
  std::string room_type;
  std::string join_rule;
  std::string world_readable;
  std::string guest_can_join;
  std::vector<std::string> aliases;
  std::vector<std::string> children_state; // for spaces
  int64_t num_joined_members{0};
  int64_t num_invited_members{0};
  int64_t num_active_members{0};
  int64_t event_count{0};
  int64_t last_active_ts{0};
  int64_t created_ts{0};
  int64_t published_ts{0};
  bool is_published{false};
  bool is_encrypted{false};
  bool is_federatable{true};
  std::string visibility; // "public" or "private"
  std::string room_version;
  std::string creator;
  std::string network_id; // third-party network id if applicable
  std::string protocol_id;
  json third_party_data;

  json to_public_chunk() const {
    json j;
    j["room_id"] = room_id;
    if (!name.empty()) j["name"] = name;
    if (!topic.empty()) j["topic"] = topic;
    j["num_joined_members"] = static_cast<int>(num_joined_members);
    if (!avatar_url.empty()) j["avatar_url"] = avatar_url;
    if (!world_readable.empty()) j["world_readable"] = world_readable;
    if (!guest_can_join.empty()) j["guest_can_join"] = guest_can_join;
    if (!canonical_alias.empty()) j["canonical_alias"] = canonical_alias;
    if (!room_type.empty()) j["room_type"] = room_type;
    if (!join_rule.empty()) j["join_rule"] = join_rule;
    if (!aliases.empty()) j["aliases"] = aliases;
    if (!network_id.empty()) j["network_id"] = network_id;
    if (!protocol_id.empty()) j["protocol_id"] = protocol_id;
    if (!room_version.empty()) j["room_version"] = room_version;
    if (last_active_ts > 0) j["last_active_ts"] = last_active_ts;
    return j;
  }

  json to_federation_chunk() const {
    json j = to_public_chunk();
    // Federation adds server info
    j["servers"] = json::array({"localhost"});
    if (is_encrypted) j["encrypted"] = true;
    if (num_active_members > 0) j["num_active_members"] = static_cast<int>(num_active_members);
    return j;
  }

  json to_full_summary() const {
    json j = to_public_chunk();
    j["num_invited_members"] = static_cast<int>(num_invited_members);
    j["num_active_members"] = static_cast<int>(num_active_members);
    j["event_count"] = static_cast<int>(event_count);
    j["is_encrypted"] = is_encrypted;
    j["is_federatable"] = is_federatable;
    j["visibility"] = visibility;
    j["is_published"] = is_published;
    if (created_ts > 0) j["created_ts"] = created_ts;
    if (published_ts > 0) j["published_ts"] = published_ts;
    if (!room_version.empty()) j["room_version"] = room_version;
    if (!creator.empty()) j["creator"] = creator;
    if (!children_state.empty()) j["children_state"] = children_state;
    return j;
  }
};

// ============================================================================
// RoomPaginationToken - Opaque pagination token
// ============================================================================

struct RoomPaginationToken {
  int64_t offset{0};
  int64_t last_active_ts{0};
  std::string last_room_id;
  std::string sort_by; // "members", "name", "recency", "default"

  std::string encode() const {
    json j;
    j["o"] = offset;
    j["t"] = last_active_ts;
    j["r"] = last_room_id;
    j["s"] = sort_by;
    return j.dump();
  }

  static RoomPaginationToken decode(const std::string& token) {
    RoomPaginationToken t;
    if (token.empty()) return t;
    try {
      json j = json::parse(token);
      if (j.contains("o") && j["o"].is_number()) t.offset = j["o"].get<int64_t>();
      if (j.contains("t") && j["t"].is_number()) t.last_active_ts = j["t"].get<int64_t>();
      if (j.contains("r") && j["r"].is_string()) t.last_room_id = j["r"].get<std::string>();
      if (j.contains("s") && j["s"].is_string()) t.sort_by = j["s"].get<std::string>();
    } catch (...) {
      // If decode fails, return zero token
    }
    return t;
  }

  bool is_start() const {
    return offset == 0 && last_room_id.empty() && last_active_ts == 0;
  }
};

// ============================================================================
// DirectorySearchFilter - Filter for public room search
// ============================================================================

struct DirectorySearchFilter {
  std::string generic_search_term;
  std::string room_type;
  std::string server;
  std::string network;
  std::string protocol;
  std::optional<int64_t> min_members;
  std::optional<int64_t> max_members;
  std::optional<bool> is_encrypted;
  std::optional<bool> is_federatable;
  std::optional<bool> is_published;
  std::optional<bool> world_readable;
  std::optional<bool> guest_can_join;
  std::optional<std::string> room_version;
  std::optional<std::string> language;
  std::string sort_order; // "members", "name", "recency"
  bool include_all_networks{false};
  bool third_party_instance_only{false};

  static DirectorySearchFilter from_json(const json& filter) {
    DirectorySearchFilter f;
    if (filter.contains("generic_search_term"))
      f.generic_search_term = safe_str(filter, "generic_search_term");
    if (filter.contains("room_type"))
      f.room_type = safe_str(filter, "room_type");
    if (filter.contains("server"))
      f.server = safe_str(filter, "server");
    if (filter.contains("network"))
      f.network = safe_str(filter, "network");
    if (filter.contains("protocol"))
      f.protocol = safe_str(filter, "protocol");
    if (filter.contains("min_members"))
      f.min_members = safe_int(filter, "min_members");
    if (filter.contains("max_members"))
      f.max_members = safe_int(filter, "max_members");
    if (filter.contains("is_encrypted"))
      f.is_encrypted = safe_bool(filter, "is_encrypted");
    if (filter.contains("is_federatable"))
      f.is_federatable = safe_bool(filter, "is_federatable");
    if (filter.contains("is_published"))
      f.is_published = safe_bool(filter, "is_published");
    if (filter.contains("world_readable"))
      f.world_readable = safe_bool(filter, "world_readable");
    if (filter.contains("guest_can_join"))
      f.guest_can_join = safe_bool(filter, "guest_can_join");
    if (filter.contains("room_version"))
      f.room_version = safe_str(filter, "room_version");
    if (filter.contains("language"))
      f.language = safe_str(filter, "language");
    if (filter.contains("sort_order"))
      f.sort_order = safe_str(filter, "sort_order");
    if (filter.contains("include_all_networks"))
      f.include_all_networks = safe_bool(filter, "include_all_networks");
    if (filter.contains("third_party_instance_only"))
      f.third_party_instance_only = safe_bool(filter, "third_party_instance_only");
    return f;
  }

  bool matches(const RoomDirectoryEntry& entry) const {
    if (!room_type.empty() && entry.room_type != room_type) return false;
    if (min_members && entry.num_joined_members < *min_members) return false;
    if (max_members && entry.num_joined_members > *max_members) return false;
    if (is_encrypted && *is_encrypted != entry.is_encrypted) return false;
    if (is_federatable && *is_federatable != entry.is_federatable) return false;
    if (is_published && *is_published != entry.is_published) return false;
    if (world_readable) {
      bool wr = (entry.world_readable == "true" || entry.world_readable == "world_readable");
      if (*world_readable != wr) return false;
    }
    if (guest_can_join) {
      bool gcj = (entry.guest_can_join == "true" || entry.guest_can_join == "can_join");
      if (*guest_can_join != gcj) return false;
    }
    if (room_version && entry.room_version != *room_version) return false;
    if (!network.empty() && entry.network_id != network) return false;
    if (!protocol.empty() && entry.protocol_id != protocol) return false;
    if (!generic_search_term.empty()) {
      auto tokens = tokenize_search(generic_search_term);
      if (!matches_search(entry.name, entry.topic, entry.canonical_alias,
                          entry.room_id, tokens))
        return false;
    }
    return true;
  }
};

// ============================================================================
// RoomPreviewData - Complete data for room preview
// ============================================================================

struct RoomPreviewData {
  std::string room_id;
  std::string name;
  std::string topic;
  std::string avatar_url;
  std::string canonical_alias;
  std::vector<std::string> alt_aliases;
  int64_t num_joined_members{0};
  int64_t num_invited_members{0};
  std::string room_type;
  bool world_readable{false};
  bool guest_can_join{false};
  bool is_encrypted{false};
  std::string join_rule;
  std::string membership; // for the requesting user
  std::string room_version;
  std::string creator;
  std::string history_visibility;
  int64_t created_ts{0};
  std::vector<std::string> servers;

  // Room preview state events
  json state_events;

  // Heroes
  json heroes;

  // Space specific
  bool is_space{false};
  std::vector<std::string> children_rooms;
  std::vector<std::string> parent_spaces;

  // Third party info
  std::string network_id;
  std::string protocol_id;
  json third_party_instance;

  json to_preview_response() const {
    json j;
    j["room_id"] = room_id;
    if (!name.empty()) j["name"] = name;
    if (!topic.empty()) j["topic"] = topic;
    j["num_joined_members"] = static_cast<int>(num_joined_members);
    if (!avatar_url.empty()) j["avatar_url"] = avatar_url;
    if (!canonical_alias.empty()) j["canonical_alias"] = canonical_alias;
    if (!alt_aliases.empty()) j["alt_aliases"] = alt_aliases;
    if (!room_type.empty()) j["room_type"] = room_type;
    j["world_readable"] = world_readable;
    j["guest_can_join"] = guest_can_join;
    j["is_encrypted"] = is_encrypted;
    if (!join_rule.empty()) j["join_rule"] = join_rule;
    if (!membership.empty()) j["membership"] = membership;
    if (!room_version.empty()) j["room_version"] = room_version;
    if (!creator.empty()) j["creator"] = creator;
    if (!servers.empty()) j["servers"] = servers;
    if (!history_visibility.empty()) j["history_visibility"] = history_visibility;
    if (is_space) j["room_type"] = "m.space";
    if (!network_id.empty()) j["network_id"] = network_id;
    if (!protocol_id.empty()) j["protocol_id"] = protocol_id;

    // Include state events if present
    if (!state_events.empty()) {
      j["state"] = json::object();
      j["state"]["events"] = state_events;
    }

    // Include heroes
    if (!heroes.empty()) {
      j["heroes"] = heroes;
    }

    // Include children / parents for spaces
    if (!children_rooms.empty()) {
      j["children"] = json::array();
      for (const auto& c : children_rooms) j["children"].push_back(c);
    }
    if (!parent_spaces.empty()) {
      j["parents"] = json::array();
      for (const auto& p : parent_spaces) j["parents"].push_back(p);
    }

    return j;
  }
};

// ============================================================================
// FederationPublicRoomChunk - Federation public room response entry
// ============================================================================

struct FederationPublicRoomChunk {
  std::string room_id;
  std::string name;
  std::string topic;
  int64_t num_joined_members{0};
  std::string avatar_url;
  std::string world_readable;
  std::string guest_can_join;
  std::string canonical_alias;
  std::string room_type;
  std::string join_rule;
  std::vector<std::string> servers;
  bool encrypted{false};

  json to_json() const {
    json j;
    j["room_id"] = room_id;
    if (!name.empty()) j["name"] = name;
    if (!topic.empty()) j["topic"] = topic;
    j["num_joined_members"] = static_cast<int>(num_joined_members);
    if (!avatar_url.empty()) j["avatar_url"] = avatar_url;
    if (!world_readable.empty()) j["world_readable"] = world_readable;
    if (!guest_can_join.empty()) j["guest_can_join"] = guest_can_join;
    if (!canonical_alias.empty()) j["canonical_alias"] = canonical_alias;
    if (!room_type.empty()) j["room_type"] = room_type;
    if (!join_rule.empty()) j["join_rule"] = join_rule;
    if (!servers.empty()) j["servers"] = servers;
    if (encrypted) j["encrypted"] = encrypted;
    return j;
  }
};

// ============================================================================
// RoomAliasInfo - Room alias resolution data
// ============================================================================

struct RoomAliasInfo {
  std::string alias;
  std::string room_id;
  std::vector<std::string> servers;
  std::string creator;
  int64_t created_ts{0};
  bool is_local{true};
  bool is_published{false};

  json to_response() const {
    json j;
    j["room_id"] = room_id;
    j["servers"] = servers.empty() ? json::array({"localhost"}) : json(servers);
    if (!creator.empty()) j["creator"] = creator;
    if (created_ts > 0) j["created_ts"] = created_ts;
    return j;
  }
};

// ============================================================================
// RoomStatistics - Statistical information for room directory
// ============================================================================

struct RoomStatistics {
  int64_t total_rooms{0};
  int64_t total_public_rooms{0};
  int64_t total_private_rooms{0};
  int64_t total_world_readable{0};
  int64_t total_encrypted{0};
  int64_t total_federatable{0};
  int64_t total_spaces{0};
  int64_t total_direct_chats{0};
  int64_t total_joined_members{0};
  int64_t avg_members_per_room{0};
  int64_t max_members_in_room{0};
  std::string max_members_room_id;
  std::map<std::string, int64_t> rooms_by_type;
  std::map<std::string, int64_t> rooms_by_version;
  std::map<std::string, int64_t> rooms_by_protocol;
  int64_t last_updated_ts{0};
  int64_t active_24h{0};
  int64_t active_7d{0};
  int64_t active_30d{0};

  json to_json() const {
    json j;
    j["total_rooms"] = static_cast<int>(total_rooms);
    j["total_public_rooms"] = static_cast<int>(total_public_rooms);
    j["total_private_rooms"] = static_cast<int>(total_private_rooms);
    j["total_world_readable"] = static_cast<int>(total_world_readable);
    j["total_encrypted"] = static_cast<int>(total_encrypted);
    j["total_federatable"] = static_cast<int>(total_federatable);
    j["total_spaces"] = static_cast<int>(total_spaces);
    j["total_direct_chats"] = static_cast<int>(total_direct_chats);
    j["total_joined_members"] = static_cast<int>(total_joined_members);
    j["avg_members_per_room"] = static_cast<int>(avg_members_per_room);
    j["max_members_in_room"] = static_cast<int>(max_members_in_room);
    if (!max_members_room_id.empty()) j["max_members_room_id"] = max_members_room_id;

    json by_type = json::object();
    for (const auto& [k, v] : rooms_by_type) by_type[k] = static_cast<int>(v);
    j["rooms_by_type"] = by_type;

    json by_version = json::object();
    for (const auto& [k, v] : rooms_by_version) by_version[k] = static_cast<int>(v);
    j["rooms_by_version"] = by_version;

    json by_protocol = json::object();
    for (const auto& [k, v] : rooms_by_protocol) by_protocol[k] = static_cast<int>(v);
    j["rooms_by_protocol"] = by_protocol;

    j["last_updated_ts"] = last_updated_ts;
    j["active_24h"] = static_cast<int>(active_24h);
    j["active_7d"] = static_cast<int>(active_7d);
    j["active_30d"] = static_cast<int>(active_30d);

    return j;
  }
};

// ============================================================================
// ThirdPartyProtocolConfig - Third party protocol configuration
// ============================================================================

struct ThirdPartyProtocolConfig {
  std::string user_fields;
  std::string location_fields;
  std::string icon;
  std::vector<std::string> field_types;
  std::vector<std::string> instances;

  json to_json() const {
    json j;
    j["user_fields"] = user_fields;
    j["location_fields"] = location_fields;
    j["icon"] = icon;
    j["field_types"] = field_types;
    j["instances"] = instances;
    return j;
  }
};

struct ThirdPartyInstance {
  std::string instance_id;
  std::string network_id;
  std::string protocol_id;
  std::string name;
  std::string desc;
  std::string icon;
  std::vector<std::string> fields;
  json custom_data;

  json to_json() const {
    json j;
    j["instance_id"] = instance_id;
    j["network_id"] = network_id;
    j["protocol_id"] = protocol_id;
    if (!name.empty()) j["name"] = name;
    if (!desc.empty()) j["desc"] = desc;
    if (!icon.empty()) j["icon"] = icon;
    if (!fields.empty()) j["fields"] = fields;
    if (!custom_data.empty()) j["custom_data"] = custom_data;
    return j;
  }
};

struct ThirdPartyLocation {
  std::string alias;
  std::string protocol;
  std::string network;
  json fields;

  json to_json() const {
    json j;
    j["alias"] = alias;
    j["protocol"] = protocol;
    j["network"] = network;
    if (!fields.empty()) j["fields"] = fields;
    return j;
  }
};

struct ThirdPartyUser {
  std::string userid;
  std::string protocol;
  std::string network;
  json fields;

  json to_json() const {
    json j;
    j["userid"] = userid;
    j["protocol"] = protocol;
    j["network"] = network;
    if (!fields.empty()) j["fields"] = fields;
    return j;
  }
};

// ============================================================================
// SpaceNode - Node in space hierarchy
// ============================================================================

struct SpaceNode {
  std::string room_id;
  std::string name;
  std::string topic;
  std::string avatar_url;
  std::string canonical_alias;
  std::string room_type;
  std::string join_rule;
  std::vector<std::string> children;
  int64_t num_joined_members{0};
  int64_t depth{0};
  bool is_encrypted{false};
  bool world_readable{false};
  bool guest_can_join{false};
  bool is_suggested{false};
  std::string suggested_reason;
  bool is_auto_join{false};
  std::string via_server;
  int64_t order{0};

  json to_summary() const {
    json j;
    j["room_id"] = room_id;
    if (!name.empty()) j["name"] = name;
    if (!topic.empty()) j["topic"] = topic;
    j["num_joined_members"] = static_cast<int>(num_joined_members);
    if (!avatar_url.empty()) j["avatar_url"] = avatar_url;
    if (!canonical_alias.empty()) j["canonical_alias"] = canonical_alias;
    if (!room_type.empty()) j["room_type"] = room_type;
    if (!join_rule.empty()) j["join_rule"] = join_rule;
    if (is_encrypted) j["is_encrypted"] = true;
    if (world_readable) j["world_readable"] = true;
    if (guest_can_join) j["guest_can_join"] = true;
    if (!via_server.empty()) j["via_server"] = via_server;
    if (is_suggested) j["suggested"] = true;
    if (!suggested_reason.empty()) j["suggested_reason"] = suggested_reason;
    if (is_auto_join) j["auto_join"] = true;
    if (order != 0) j["order"] = static_cast<int>(order);
    return j;
  }

  json to_tree_node() const {
    json j = to_summary();
    j["children_state"] = json::array();
    for (const auto& c : children) j["children_state"].push_back(c);
    j["depth"] = static_cast<int>(depth);
    return j;
  }
};

// ============================================================================
// RoomDiscoveryCache - LRU cache for discovery data
// ============================================================================

template<typename K, typename V>
class DiscoveryLRUCache {
  struct Node {
    K key;
    V value;
    Node* prev{nullptr};
    Node* next{nullptr};
  };

  size_t capacity_;
  std::unordered_map<K, Node*> map_;
  Node* head_{nullptr};
  Node* tail_{nullptr};
  std::mutex mutex_;

  void move_to_front(Node* node) {
    if (node == head_) return;
    if (node->prev) node->prev->next = node->next;
    if (node->next) node->next->prev = node->prev;
    if (node == tail_) tail_ = node->prev;
    node->next = head_;
    node->prev = nullptr;
    if (head_) head_->prev = node;
    head_ = node;
    if (!tail_) tail_ = node;
  }

  void evict() {
    if (!tail_) return;
    Node* old = tail_;
    tail_ = tail_->prev;
    if (tail_) tail_->next = nullptr;
    else head_ = nullptr;
    map_.erase(old->key);
    delete old;
  }

public:
  explicit DiscoveryLRUCache(size_t capacity) : capacity_(std::max(capacity, size_t(1))) {}
  ~DiscoveryLRUCache() {
    while (head_) {
      Node* n = head_;
      head_ = head_->next;
      delete n;
    }
  }

  std::optional<V> get(const K& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = map_.find(key);
    if (it == map_.end()) return std::nullopt;
    move_to_front(it->second);
    return it->second->value;
  }

  void put(const K& key, const V& value) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = map_.find(key);
    if (it != map_.end()) {
      it->second->value = value;
      move_to_front(it->second);
      return;
    }
    while (map_.size() >= capacity_) evict();
    Node* node = new Node{key, value};
    node->next = head_;
    if (head_) head_->prev = node;
    head_ = node;
    if (!tail_) tail_ = node;
    map_[key] = node;
  }

  void clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    while (head_) {
      Node* n = head_;
      head_ = head_->next;
      map_.erase(n->key);
      delete n;
    }
    tail_ = nullptr;
  }

  size_t size() const { return map_.size(); }
};

// ============================================================================
// RoomDiscoveryStore - In-memory store for room discovery
// ============================================================================

class RoomDiscoveryStore {
public:
  RoomDiscoveryStore() = default;

  // --- Room directory entries ---
  void add_room_entry(const RoomDirectoryEntry& entry) {
    std::lock_guard lock(mutex_);
    entries_[entry.room_id] = entry;
    if (entry.is_published) {
      published_ids_.insert(entry.room_id);
    }
    if (entry.room_type == "m.space") {
      space_ids_.insert(entry.room_id);
    }
  }

  void remove_room_entry(const std::string& room_id) {
    std::lock_guard lock(mutex_);
    entries_.erase(room_id);
    published_ids_.erase(room_id);
    space_ids_.erase(room_id);
  }

  std::optional<RoomDirectoryEntry> get_room_entry(const std::string& room_id) {
    std::lock_guard lock(mutex_);
    auto it = entries_.find(room_id);
    if (it == entries_.end()) return std::nullopt;
    return it->second;
  }

  void update_room_entry(const std::string& room_id,
                          std::function<void(RoomDirectoryEntry&)> updater) {
    std::lock_guard lock(mutex_);
    auto it = entries_.find(room_id);
    if (it != entries_.end()) {
      updater(it->second);
      if (it->second.is_published) published_ids_.insert(room_id);
      else published_ids_.erase(room_id);
      if (it->second.room_type == "m.space") space_ids_.insert(room_id);
      else space_ids_.erase(room_id);
    }
  }

  void set_room_visibility(const std::string& room_id, const std::string& visibility) {
    std::lock_guard lock(mutex_);
    auto it = entries_.find(room_id);
    if (it != entries_.end()) {
      it->second.visibility = visibility;
      it->second.is_published = (visibility == "public");
      if (it->second.is_published) published_ids_.insert(room_id);
      else published_ids_.erase(room_id);
    } else {
      RoomDirectoryEntry entry;
      entry.room_id = room_id;
      entry.visibility = visibility;
      entry.is_published = (visibility == "public");
      entries_[room_id] = entry;
      if (entry.is_published) published_ids_.insert(room_id);
    }
  }

  std::string get_room_visibility(const std::string& room_id) {
    std::lock_guard lock(mutex_);
    auto it = entries_.find(room_id);
    if (it == entries_.end()) return "private";
    return it->second.visibility;
  }

  std::vector<RoomDirectoryEntry> get_all_rooms() {
    std::lock_guard lock(mutex_);
    std::vector<RoomDirectoryEntry> result;
    result.reserve(entries_.size());
    for (const auto& [id, entry] : entries_) {
      result.push_back(entry);
    }
    return result;
  }

  std::vector<RoomDirectoryEntry> get_published_rooms() {
    std::lock_guard lock(mutex_);
    std::vector<RoomDirectoryEntry> result;
    for (const auto& id : published_ids_) {
      auto it = entries_.find(id);
      if (it != entries_.end()) result.push_back(it->second);
    }
    return result;
  }

  std::vector<RoomDirectoryEntry> get_space_rooms() {
    std::lock_guard lock(mutex_);
    std::vector<RoomDirectoryEntry> result;
    for (const auto& id : space_ids_) {
      auto it = entries_.find(id);
      if (it != entries_.end()) result.push_back(it->second);
    }
    return result;
  }

  // --- Aliases ---
  void add_alias(const std::string& alias, const std::string& room_id,
                  const std::vector<std::string>& servers = {},
                  const std::string& creator = "") {
    std::lock_guard lock(alias_mutex_);
    alias_to_room_[alias] = {room_id, servers.empty() ? std::vector<std::string>{"localhost"} : servers, creator};
    room_to_aliases_[room_id].push_back(alias);
  }

  void remove_alias(const std::string& alias) {
    std::lock_guard lock(alias_mutex_);
    auto it = alias_to_room_.find(alias);
    if (it != alias_to_room_.end()) {
      auto& aliases = room_to_aliases_[it->second.room_id];
      aliases.erase(std::remove(aliases.begin(), aliases.end(), alias), aliases.end());
      alias_to_room_.erase(it);
    }
  }

  std::optional<RoomAliasInfo> resolve_alias(const std::string& alias) {
    std::lock_guard lock(alias_mutex_);
    auto it = alias_to_room_.find(alias);
    if (it == alias_to_room_.end()) return std::nullopt;
    RoomAliasInfo info;
    info.alias = alias;
    info.room_id = it->second.room_id;
    info.servers = it->second.servers;
    info.creator = it->second.creator;
    info.is_local = true;
    return info;
  }

  std::vector<std::string> get_room_aliases(const std::string& room_id) {
    std::lock_guard lock(alias_mutex_);
    auto it = room_to_aliases_.find(room_id);
    if (it == room_to_aliases_.end()) return {};
    return it->second;
  }

  std::vector<std::pair<std::string, std::string>> get_all_aliases() {
    std::lock_guard lock(alias_mutex_);
    std::vector<std::pair<std::string, std::string>> result;
    for (const auto& [alias, info] : alias_to_room_) {
      result.emplace_back(alias, info.room_id);
    }
    return result;
  }

  // --- Third party protocols ---
  void register_protocol(const std::string& name, const ThirdPartyProtocolConfig& config) {
    std::lock_guard lock(protocol_mutex_);
    protocols_[name] = config;
  }

  std::optional<ThirdPartyProtocolConfig> get_protocol(const std::string& name) {
    std::lock_guard lock(protocol_mutex_);
    auto it = protocols_.find(name);
    if (it == protocols_.end()) return std::nullopt;
    return it->second;
  }

  std::unordered_map<std::string, ThirdPartyProtocolConfig> get_all_protocols() {
    std::lock_guard lock(protocol_mutex_);
    return protocols_;
  }

  void add_third_party_instance(const ThirdPartyInstance& instance) {
    std::lock_guard lock(tp_instance_mutex_);
    tp_instances_[instance.instance_id] = instance;
  }

  std::vector<ThirdPartyInstance> get_third_party_instances(
      const std::string& protocol = "", const std::string& network = "") {
    std::lock_guard lock(tp_instance_mutex_);
    std::vector<ThirdPartyInstance> result;
    for (const auto& [id, inst] : tp_instances_) {
      if (!protocol.empty() && inst.protocol_id != protocol) continue;
      if (!network.empty() && inst.network_id != network) continue;
      result.push_back(inst);
    }
    return result;
  }

  void add_third_party_location(const ThirdPartyLocation& location) {
    std::lock_guard lock(tp_location_mutex_);
    tp_locations_.push_back(location);
  }

  std::vector<ThirdPartyLocation> get_third_party_locations(
      const std::string& protocol = "") {
    std::lock_guard lock(tp_location_mutex_);
    if (protocol.empty()) return tp_locations_;
    std::vector<ThirdPartyLocation> result;
    for (const auto& loc : tp_locations_) {
      if (loc.protocol == protocol) result.push_back(loc);
    }
    return result;
  }

  void add_third_party_user(const ThirdPartyUser& user) {
    std::lock_guard lock(tp_user_mutex_);
    tp_users_.push_back(user);
  }

  std::vector<ThirdPartyUser> get_third_party_users(
      const std::string& protocol = "") {
    std::lock_guard lock(tp_user_mutex_);
    if (protocol.empty()) return tp_users_;
    std::vector<ThirdPartyUser> result;
    for (const auto& u : tp_users_) {
      if (u.protocol == protocol) result.push_back(u);
    }
    return result;
  }

  // --- Space hierarchy ---
  void add_space_child(const std::string& space_id, const SpaceNode& node) {
    std::lock_guard lock(space_mutex_);
    space_children_[space_id].push_back(node);
  }

  void set_space_children(const std::string& space_id,
                           const std::vector<SpaceNode>& children) {
    std::lock_guard lock(space_mutex_);
    space_children_[space_id] = children;
  }

  std::vector<SpaceNode> get_space_children(const std::string& space_id) {
    std::lock_guard lock(space_mutex_);
    auto it = space_children_.find(space_id);
    if (it == space_children_.end()) return {};
    return it->second;
  }

  void add_space_parent(const std::string& room_id, const std::string& parent_id) {
    std::lock_guard lock(space_mutex_);
    space_parents_[room_id].push_back(parent_id);
  }

  std::vector<std::string> get_space_parents(const std::string& room_id) {
    std::lock_guard lock(space_mutex_);
    auto it = space_parents_.find(room_id);
    if (it == space_parents_.end()) return {};
    return it->second;
  }

  // --- Room version ---
  void set_room_version(const std::string& room_id, const std::string& version) {
    std::lock_guard lock(version_mutex_);
    room_versions_[room_id] = version;
  }

  std::optional<std::string> get_room_version(const std::string& room_id) {
    std::lock_guard lock(version_mutex_);
    auto it = room_versions_.find(room_id);
    if (it == room_versions_.end()) return std::nullopt;
    return it->second;
  }

  // --- Statistics ---
  void compute_statistics() {
    std::lock_guard lock(mutex_);
    RoomStatistics stats;
    stats.last_updated_ts = now_ms();
    int64_t cutoff_24h = now_ms() - 86400000;
    int64_t cutoff_7d = now_ms() - 604800000;
    int64_t cutoff_30d = now_ms() - 2592000000;

    for (const auto& [id, entry] : entries_) {
      stats.total_rooms++;
      if (entry.is_published) stats.total_public_rooms++;
      else stats.total_private_rooms++;
      if (entry.world_readable == "true" || entry.world_readable == "world_readable")
        stats.total_world_readable++;
      if (entry.is_encrypted) stats.total_encrypted++;
      if (entry.is_federatable) stats.total_federatable++;
      if (entry.room_type == "m.space") stats.total_spaces++;

      stats.total_joined_members += entry.num_joined_members;
      if (entry.num_joined_members > stats.max_members_in_room) {
        stats.max_members_in_room = entry.num_joined_members;
        stats.max_members_room_id = id;
      }

      std::string type_key = entry.room_type.empty() ? "room" : entry.room_type;
      stats.rooms_by_type[type_key]++;

      std::string version_key = entry.room_version.empty() ? "unknown" : entry.room_version;
      stats.rooms_by_version[version_key]++;

      if (!entry.protocol_id.empty()) {
        stats.rooms_by_protocol[entry.protocol_id]++;
      }

      if (entry.last_active_ts > cutoff_24h) stats.active_24h++;
      if (entry.last_active_ts > cutoff_7d) stats.active_7d++;
      if (entry.last_active_ts > cutoff_30d) stats.active_30d++;
    }

    if (stats.total_rooms > 0) {
      stats.avg_members_per_room = stats.total_joined_members / stats.total_rooms;
    }

    std::lock_guard stats_lock(stats_mutex_);
    statistics_ = stats;
  }

  RoomStatistics get_statistics() {
    std::lock_guard lock(stats_mutex_);
    return statistics_;
  }

private:
  struct AliasInfo {
    std::string room_id;
    std::vector<std::string> servers;
    std::string creator;
  };

  std::mutex mutex_;
  std::unordered_map<std::string, RoomDirectoryEntry> entries_;
  std::unordered_set<std::string> published_ids_;
  std::unordered_set<std::string> space_ids_;

  std::mutex alias_mutex_;
  std::unordered_map<std::string, AliasInfo> alias_to_room_;
  std::unordered_map<std::string, std::vector<std::string>> room_to_aliases_;

  std::mutex protocol_mutex_;
  std::unordered_map<std::string, ThirdPartyProtocolConfig> protocols_;

  std::mutex tp_instance_mutex_;
  std::unordered_map<std::string, ThirdPartyInstance> tp_instances_;

  std::mutex tp_location_mutex_;
  std::vector<ThirdPartyLocation> tp_locations_;

  std::mutex tp_user_mutex_;
  std::vector<ThirdPartyUser> tp_users_;

  std::mutex space_mutex_;
  std::unordered_map<std::string, std::vector<SpaceNode>> space_children_;
  std::unordered_map<std::string, std::vector<std::string>> space_parents_;

  std::mutex version_mutex_;
  std::unordered_map<std::string, std::string> room_versions_;

  std::mutex stats_mutex_;
  RoomStatistics statistics_;
};

// ============================================================================
// RoomDiscoveryHandler -- Main handler class
// ============================================================================

class RoomDiscoveryHandler {
public:
  RoomDiscoveryHandler() {
    init_default_protocols();
    init_bootstrap_rooms();
  }

  explicit RoomDiscoveryHandler(DatabasePool& db) : db_(&db) {
    init_default_protocols();
    init_bootstrap_rooms();
  }

  // ==========================================================================
  // 1. Public Room Listing API (GET /publicRooms)
  // ==========================================================================
  json list_public_rooms(const std::string& server = "",
                          int limit = 50,
                          const std::string& since = "",
                          const std::string& search_term = "",
                          const std::string& network = "",
                          bool include_all_networks = false,
                          bool third_party_instance_only = false) {
    json result;

    // Clamp limit
    if (limit <= 0) limit = 50;
    if (limit > 500) limit = 500;

    // Get published rooms
    auto all_rooms = store_.get_published_rooms();

    // Apply network filter
    if (!network.empty()) {
      all_rooms.erase(std::remove_if(all_rooms.begin(), all_rooms.end(),
        [&](const RoomDirectoryEntry& e) {
          if (include_all_networks) return false;
          if (third_party_instance_only) {
            return e.network_id != network;
          }
          return e.network_id != network && !e.network_id.empty();
        }), all_rooms.end());
    }

    if (third_party_instance_only) {
      all_rooms.erase(std::remove_if(all_rooms.begin(), all_rooms.end(),
        [](const RoomDirectoryEntry& e) {
          return e.network_id.empty();
        }), all_rooms.end());
    }

    // Apply server filter
    if (!server.empty()) {
      all_rooms.erase(std::remove_if(all_rooms.begin(), all_rooms.end(),
        [&](const RoomDirectoryEntry& e) {
          return e.room_id.find(server) == std::string::npos;
        }), all_rooms.end());
    }

    // Apply search filter
    std::vector<std::string> tokens;
    if (!search_term.empty()) {
      tokens = tokenize_search(search_term);
      all_rooms.erase(std::remove_if(all_rooms.begin(), all_rooms.end(),
        [&](const RoomDirectoryEntry& e) {
          return !matches_search(e.name, e.topic, e.canonical_alias, e.room_id, tokens);
        }), all_rooms.end());
    }

    // Sort by recency (default)
    std::sort(all_rooms.begin(), all_rooms.end(),
      [](const RoomDirectoryEntry& a, const RoomDirectoryEntry& b) {
        if (a.num_joined_members != b.num_joined_members)
          return a.num_joined_members > b.num_joined_members;
        return a.last_active_ts > b.last_active_ts;
      });

    // Decode pagination
    RoomPaginationToken pag_token = RoomPaginationToken::decode(since);
    int64_t start_offset = pag_token.offset;

    // Build chunk
    json chunk = json::array();
    int64_t end_offset = start_offset;
    for (int64_t i = start_offset; i < static_cast<int64_t>(all_rooms.size()) &&
         static_cast<int64_t>(chunk.size()) < limit; i++) {
      chunk.push_back(all_rooms[i].to_public_chunk());
      end_offset = i + 1;
    }

    // Pagination token for next batch
    RoomPaginationToken next_token;
    if (end_offset < static_cast<int64_t>(all_rooms.size())) {
      next_token.offset = end_offset;
      next_token.last_active_ts = (end_offset > 0 && end_offset <= static_cast<int64_t>(all_rooms.size()))
        ? all_rooms[end_offset - 1].last_active_ts : 0;
    }

    result["chunk"] = chunk;
    result["next_batch"] = next_token.is_start() ? "" : next_token.encode();
    result["prev_batch"] = since;
    result["total_room_count_estimate"] = static_cast<int>(all_rooms.size());

    return result;
  }

  // ==========================================================================
  // 2. Public Room Search (POST /publicRooms with filter)
  // ==========================================================================
  json search_public_rooms(const json& filter_json,
                            int limit = 50,
                            const std::string& since = "",
                            const std::string& server = "") {
    json result;
    if (limit <= 0) limit = 50;
    if (limit > 500) limit = 500;

    DirectorySearchFilter filter = DirectorySearchFilter::from_json(filter_json);

    auto all_rooms = store_.get_published_rooms();

    // Apply server filter
    if (!server.empty()) {
      all_rooms.erase(std::remove_if(all_rooms.begin(), all_rooms.end(),
        [&](const RoomDirectoryEntry& e) {
          return e.room_id.find(server) == std::string::npos;
        }), all_rooms.end());
    }

    // Apply search filter
    std::vector<RoomDirectoryEntry> filtered;
    for (const auto& entry : all_rooms) {
      if (filter.matches(entry)) {
        filtered.push_back(entry);
      }
    }

    // Sort
    sort_room_entries(filtered, filter.sort_order);

    // Paginate
    RoomPaginationToken pag_token = RoomPaginationToken::decode(since);
    if (!filter.sort_order.empty()) pag_token.sort_by = filter.sort_order;

    int64_t start = pag_token.offset;
    json chunk = json::array();
    int64_t end = start;
    for (int64_t i = start; i < static_cast<int64_t>(filtered.size()) &&
         static_cast<int64_t>(chunk.size()) < limit; i++) {
      chunk.push_back(filtered[i].to_public_chunk());
      end = i + 1;
    }

    RoomPaginationToken next_token;
    if (end < static_cast<int64_t>(filtered.size())) {
      next_token.offset = end;
      next_token.sort_by = filter.sort_order;
    }

    result["chunk"] = chunk;
    result["next_batch"] = next_token.is_start() ? "" : next_token.encode();
    result["prev_batch"] = since;
    result["total_room_count_estimate"] = static_cast<int>(filtered.size());

    return result;
  }

  // ==========================================================================
  // 3. Room Preview for non-members (GET /rooms/{roomId}/preview)
  // ==========================================================================
  json get_room_preview(const std::string& room_id,
                         const std::string& user_id = "",
                         const json& via = json::array()) {
    // Check cache
    {
      std::string cache_key = "preview:" + room_id + ":" + user_id;
      auto cached = preview_cache_.get(cache_key);
      if (cached) return *cached;
    }

    RoomPreviewData preview;
    preview.room_id = room_id;

    // Load from DB if available
    if (db_) {
      preview = load_preview_from_db(room_id, user_id);
    } else {
      preview = build_preview_from_store(room_id, user_id);
    }

    // Apply via servers if provided
    if (via.is_array()) {
      for (const auto& s : via) {
        if (s.is_string()) preview.servers.push_back(s.get<std::string>());
      }
    }
    if (preview.servers.empty()) {
      preview.servers.push_back("localhost");
    }

    // Determine membership for the requesting user
    if (!user_id.empty()) {
      preview.membership = check_membership(room_id, user_id);
    } else {
      preview.membership = "leave";
    }

    json response = preview.to_preview_response();

    // Cache
    {
      std::string cache_key = "preview:" + room_id + ":" + user_id;
      preview_cache_.put(cache_key, response);
    }

    return response;
  }

  // ==========================================================================
  // 4. Room Preview for Unauthenticated users
  // ==========================================================================
  json get_room_preview_unauthenticated(const std::string& room_id) {
    // Check cache
    std::string cache_key = "preview:unauth:" + room_id;
    auto cached = preview_cache_.get(cache_key);
    if (cached) return *cached;

    auto entry = store_.get_room_entry(room_id);
    if (!entry) {
      return json({{"errcode", "M_NOT_FOUND"}, {"error", "Room not found"}});
    }

    // Unauthenticated users can only see world_readable rooms
    bool is_wr = (entry->world_readable == "true" || entry->world_readable == "world_readable");
    if (!is_wr) {
      return json({{"errcode", "M_FORBIDDEN"},
                   {"error", "Room is not world-readable"}});
    }

    json preview;
    preview["room_id"] = room_id;
    preview["name"] = entry->name;
    preview["topic"] = entry->topic;
    preview["avatar_url"] = entry->avatar_url;
    preview["canonical_alias"] = entry->canonical_alias;
    preview["num_joined_members"] = static_cast<int>(entry->num_joined_members);
    preview["room_type"] = entry->room_type;
    preview["world_readable"] = true;
    preview["guest_can_join"] = (entry->guest_can_join == "can_join");
    preview["join_rule"] = entry->join_rule;
    preview["room_version"] = entry->room_version;
    preview["is_encrypted"] = entry->is_encrypted;
    preview["membership"] = "leave";
    preview["servers"] = json::array({"localhost"});

    preview_cache_.put(cache_key, preview);
    return preview;
  }

  // ==========================================================================
  // 5. Room Discovery via Alias (GET /directory/room/{alias})
  // ==========================================================================
  json discover_room_by_alias(const std::string& alias) {
    if (!validate_room_alias(alias)) {
      return json({{"errcode", "M_INVALID_PARAM"},
                   {"error", "Invalid room alias format"}});
    }

    auto info = store_.resolve_alias(alias);
    if (!info) {
      return json({{"errcode", "M_NOT_FOUND"},
                   {"error", "Room alias not found"}});
    }

    return info->to_response();
  }

  // ==========================================================================
  // 6. Room Directory Management (PUT /directory/room/{alias})
  // ==========================================================================
  json create_alias(const std::string& alias, const std::string& room_id,
                     const std::string& user_id = "",
                     const std::vector<std::string>& servers = {}) {
    if (!validate_room_alias(alias)) {
      return json({{"errcode", "M_INVALID_PARAM"},
                   {"error", "Invalid alias format"}});
    }
    if (!validate_room_id(room_id)) {
      return json({{"errcode", "M_INVALID_PARAM"},
                   {"error", "Invalid room ID"}});
    }

    // Check if alias already exists
    auto existing = store_.resolve_alias(alias);
    if (existing) {
      // Alias already points to a room
      return json({{"errcode", "M_ALIAS_IN_USE"},
                   {"error", "Room alias already in use"}});
    }

    // Validate server authority
    std::string alias_server = extract_server_name(alias);
    if (alias_server.empty()) {
      return json({{"errcode", "M_INVALID_PARAM"},
                   {"error", "Alias must include server name"}});
    }

    auto srv_list = servers.empty() ? std::vector<std::string>{"localhost"} : servers;
    store_.add_alias(alias, room_id, srv_list, user_id);

    // Update room entry with canonical alias if not set
    store_.update_room_entry(room_id, [&](RoomDirectoryEntry& e) {
      if (e.canonical_alias.empty()) {
        e.canonical_alias = alias;
      }
      auto& als = e.aliases;
      if (std::find(als.begin(), als.end(), alias) == als.end()) {
        als.push_back(alias);
      }
    });

    if (db_) {
      DirectoryStore dir(*db_);
      dir.create_alias(alias, room_id, user_id, srv_list);
    }

    return json::object();
  }

  // ==========================================================================
  // 7. Delete Alias (DELETE /directory/room/{alias})
  // ==========================================================================
  json delete_alias(const std::string& alias, const std::string& user_id = "") {
    if (!validate_room_alias(alias)) {
      return json({{"errcode", "M_INVALID_PARAM"},
                   {"error", "Invalid alias format"}});
    }

    auto info = store_.resolve_alias(alias);
    if (!info) {
      return json({{"errcode", "M_NOT_FOUND"},
                   {"error", "Room alias not found"}});
    }

    store_.remove_alias(alias);

    // Remove from room entry aliases
    store_.update_room_entry(info->room_id, [&](RoomDirectoryEntry& e) {
      auto& als = e.aliases;
      als.erase(std::remove(als.begin(), als.end(), alias), als.end());
      if (e.canonical_alias == alias) {
        e.canonical_alias = als.empty() ? "" : als[0];
      }
    });

    if (db_) {
      DirectoryStore dir(*db_);
      dir.delete_alias(alias);
    }

    return json::object();
  }

  // ==========================================================================
  // 8. Get Room Local Aliases
  // ==========================================================================
  json get_room_local_aliases(const std::string& room_id) {
    auto aliases = store_.get_room_aliases(room_id);
    return json(aliases);
  }

  // ==========================================================================
  // 9. Third-Party Protocol Listing (GET /thirdparty/protocols)
  // ==========================================================================
  json list_third_party_protocols() {
    auto all = store_.get_all_protocols();
    json result = json::object();
    for (const auto& [name, cfg] : all) {
      result[name] = cfg.to_json();
    }
    return result;
  }

  // ==========================================================================
  // 10. Third-Party Protocol Detail (GET /thirdparty/protocol/{protocol})
  // ==========================================================================
  json get_third_party_protocol(const std::string& protocol) {
    auto cfg = store_.get_protocol(protocol);
    if (!cfg) {
      return json({{"errcode", "M_NOT_FOUND"},
                   {"error", "Protocol not found"}});
    }
    return cfg->to_json();
  }

  // ==========================================================================
  // 11. Third-Party User Query (GET /thirdparty/user/{protocol})
  // ==========================================================================
  json query_third_party_user(const std::string& protocol,
                               const json& fields) {
    auto cfg = store_.get_protocol(protocol);
    if (!cfg) {
      return json({{"errcode", "M_NOT_FOUND"},
                   {"error", "Protocol not found"}});
    }

    auto users = store_.get_third_party_users(protocol);

    // Filter by fields if provided
    if (!fields.empty()) {
      users.erase(std::remove_if(users.begin(), users.end(),
        [&](const ThirdPartyUser& u) {
          for (auto it = fields.begin(); it != fields.end(); ++it) {
            std::string key = it.key();
            if (u.fields.contains(key)) {
              std::string field_val = safe_str(u.fields, key);
              std::string search_val = safe_str(fields, key);
              if (field_val.find(search_val) == std::string::npos) return true;
            } else {
              return true;
            }
          }
          return false;
        }), users.end());
    }

    json result = json::array();
    for (const auto& u : users) {
      result.push_back(u.to_json());
    }
    return result;
  }

  // ==========================================================================
  // 12. Third-Party Location Query (GET /thirdparty/location/{protocol})
  // ==========================================================================
  json query_third_party_location(const std::string& protocol,
                                   const json& fields) {
    auto cfg = store_.get_protocol(protocol);
    if (!cfg) {
      return json({{"errcode", "M_NOT_FOUND"},
                   {"error", "Protocol not found"}});
    }

    auto locations = store_.get_third_party_locations(protocol);

    if (!fields.empty()) {
      locations.erase(std::remove_if(locations.begin(), locations.end(),
        [&](const ThirdPartyLocation& l) {
          for (auto it = fields.begin(); it != fields.end(); ++it) {
            std::string key = it.key();
            if (l.fields.contains(key)) {
              std::string field_val = safe_str(l.fields, key);
              std::string search_val = safe_str(fields, key);
              if (field_val.find(search_val) == std::string::npos) return true;
            } else {
              return true;
            }
          }
          return false;
        }), locations.end());
    }

    json result = json::array();
    for (const auto& l : locations) {
      result.push_back(l.to_json());
    }
    return result;
  }

  // ==========================================================================
  // 13. Room Canonical Alias Management
  // ==========================================================================
  json get_canonical_alias(const std::string& room_id) {
    auto entry = store_.get_room_entry(room_id);
    if (!entry) return json({{"alias", ""}});
    return json({{"alias", entry->canonical_alias}});
  }

  json set_canonical_alias(const std::string& room_id,
                            const std::string& alias,
                            const std::string& user_id = "") {
    if (!validate_room_id(room_id)) {
      return json({{"errcode", "M_INVALID_PARAM"}, {"error", "Invalid room ID"}});
    }

    // Verify alias exists
    if (!alias.empty()) {
      auto info = store_.resolve_alias(alias);
      if (!info) {
        return json({{"errcode", "M_NOT_FOUND"},
                     {"error", "Alias does not exist"}});
      }
      if (info->room_id != room_id) {
        return json({{"errcode", "M_INVALID_PARAM"},
                     {"error", "Alias does not point to this room"}});
      }
    }

    store_.update_room_entry(room_id, [&](RoomDirectoryEntry& e) {
      e.canonical_alias = alias;
    });

    return json::object();
  }

  // ==========================================================================
  // 14. Room Alt Aliases Management
  // ==========================================================================
  json get_alt_aliases(const std::string& room_id) {
    auto entry = store_.get_room_entry(room_id);
    if (!entry) return json::array();
    json result = json::array();
    for (const auto& a : entry->aliases) {
      if (a != entry->canonical_alias) result.push_back(a);
    }
    return result;
  }

  json add_alt_alias(const std::string& room_id, const std::string& alias,
                      const std::string& user_id = "") {
    if (!validate_room_alias(alias)) {
      return json({{"errcode", "M_INVALID_PARAM"}, {"error", "Invalid alias"}});
    }

    auto info = store_.resolve_alias(alias);
    if (!info) {
      return json({{"errcode", "M_NOT_FOUND"}, {"error", "Alias not found"}});
    }
    if (info->room_id != room_id) {
      return json({{"errcode", "M_INVALID_PARAM"},
                   {"error", "Alias does not point to this room"}});
    }

    store_.update_room_entry(room_id, [&](RoomDirectoryEntry& e) {
      auto& als = e.aliases;
      if (std::find(als.begin(), als.end(), alias) == als.end()) {
        als.push_back(alias);
      }
    });

    return json::object();
  }

  json remove_alt_alias(const std::string& room_id, const std::string& alias,
                         const std::string& user_id = "") {
    store_.update_room_entry(room_id, [&](RoomDirectoryEntry& e) {
      if (e.canonical_alias == alias) return; // Don't remove canonical via this path
      auto& als = e.aliases;
      als.erase(std::remove(als.begin(), als.end(), alias), als.end());
    });
    return json::object();
  }

  // ==========================================================================
  // 15. Room Visibility Management
  // ==========================================================================
  json get_room_visibility(const std::string& room_id) {
    auto vis = store_.get_room_visibility(room_id);
    return json({{"visibility", vis}});
  }

  json set_room_visibility(const std::string& room_id,
                            const std::string& visibility,
                            const std::string& user_id = "") {
    if (visibility != "public" && visibility != "private") {
      return json({{"errcode", "M_INVALID_PARAM"},
                   {"error", "Visibility must be 'public' or 'private'"}});
    }

    store_.set_room_visibility(room_id, visibility);

    if (db_) {
      DirectoryStore dir(*db_);
      dir.set_room_visibility(room_id, visibility);
    }

    return json::object();
  }

  // ==========================================================================
  // 16. Room Publishing to Directory
  // ==========================================================================
  json publish_room(const std::string& room_id, const std::string& user_id = "") {
    store_.update_room_entry(room_id, [&](RoomDirectoryEntry& e) {
      e.is_published = true;
      e.visibility = "public";
      e.published_ts = now_ms();
    });

    // Ensure entry exists
    auto entry = store_.get_room_entry(room_id);
    if (!entry) {
      RoomDirectoryEntry new_entry;
      new_entry.room_id = room_id;
      new_entry.is_published = true;
      new_entry.visibility = "public";
      new_entry.published_ts = now_ms();
      store_.add_room_entry(new_entry);
    }

    return json::object();
  }

  // ==========================================================================
  // 17. Room Unpublishing from Directory
  // ==========================================================================
  json unpublish_room(const std::string& room_id, const std::string& user_id = "") {
    store_.update_room_entry(room_id, [](RoomDirectoryEntry& e) {
      e.is_published = false;
      e.visibility = "private";
    });

    return json::object();
  }

  // ==========================================================================
  // 18. Room Summary for Unauthenticated
  // ==========================================================================
  json get_room_summary_unauthenticated(const std::string& room_id) {
    auto entry = store_.get_room_entry(room_id);
    if (!entry) {
      return json({{"errcode", "M_NOT_FOUND"}, {"error", "Room not found"}});
    }

    bool is_wr = (entry->world_readable == "true" || entry->world_readable == "world_readable");
    if (!is_wr) {
      return json({{"errcode", "M_FORBIDDEN"},
                   {"error", "Room is not world-readable"}});
    }

    // Build a minimal summary suitable for unauthenticated access
    json summary;
    summary["room_id"] = room_id;
    if (!entry->name.empty()) summary["name"] = entry->name;
    if (!entry->topic.empty()) summary["topic"] = entry->topic;
    if (!entry->avatar_url.empty()) summary["avatar_url"] = entry->avatar_url;
    if (!entry->canonical_alias.empty()) summary["canonical_alias"] = entry->canonical_alias;
    summary["num_joined_members"] = static_cast<int>(entry->num_joined_members);
    if (!entry->room_type.empty()) summary["room_type"] = entry->room_type;
    summary["world_readable"] = true;
    summary["guest_can_join"] = (entry->guest_can_join == "can_join");
    if (!entry->join_rule.empty()) summary["join_rule"] = entry->join_rule;
    summary["is_encrypted"] = entry->is_encrypted;
    if (!entry->room_version.empty()) summary["room_version"] = entry->room_version;
    summary["servers"] = json::array({"localhost"});

    // Include alt aliases
    json alt_aliases = json::array();
    for (const auto& a : entry->aliases) {
      if (a != entry->canonical_alias) alt_aliases.push_back(a);
    }
    if (!alt_aliases.empty()) summary["alt_aliases"] = alt_aliases;

    return summary;
  }

  // ==========================================================================
  // 19. Space Room Discovery / Space Hierarchy
  // ==========================================================================
  json discover_space_hierarchy(const std::string& space_id,
                                 int max_depth = 3,
                                 int limit_per_space = 50,
                                 const std::string& user_id = "",
                                 bool suggested_only = false) {
    // Check cache
    std::string cache_key = "space:" + space_id + ":" + std::to_string(max_depth) +
                            ":" + std::to_string(limit_per_space) + ":" +
                            (suggested_only ? "1" : "0");
    auto cached = space_cache_.get(cache_key);
    if (cached) return *cached;

    auto entry = store_.get_room_entry(space_id);
    if (!entry || entry->room_type != "m.space") {
      return json({{"errcode", "M_NOT_FOUND"},
                   {"error", "Space not found"}});
    }

    json result;
    result["room_id"] = space_id;
    if (!entry->name.empty()) result["name"] = entry->name;
    result["num_joined_members"] = static_cast<int>(entry->num_joined_members);
    if (!entry->topic.empty()) result["topic"] = entry->topic;
    if (!entry->avatar_url.empty()) result["avatar_url"] = entry->avatar_url;
    if (!entry->canonical_alias.empty()) result["canonical_alias"] = entry->canonical_alias;
    if (!entry->join_rule.empty()) result["join_rule"] = entry->join_rule;
    result["world_readable"] = (entry->world_readable == "world_readable");
    result["guest_can_join"] = (entry->guest_can_join == "can_join");

    // Traverse space hierarchy
    json children_json = json::array();
    std::unordered_set<std::string> visited;
    traverse_space(space_id, children_json, max_depth, 0, limit_per_space, 
                   visited, suggested_only);

    result["children_state"] = children_json;

    // Include rooms
    json rooms_json = json::array();
    auto children = store_.get_space_children(space_id);
    for (const auto& child : children) {
      if (suggested_only && !child.is_suggested) continue;
      json room_summary = child.to_summary();
      // Check membership
      if (!user_id.empty()) {
        std::string membership = check_membership(child.room_id, user_id);
        room_summary["membership"] = membership;
      }
      rooms_json.push_back(room_summary);
    }
    result["rooms"] = rooms_json;

    space_cache_.put(cache_key, result);
    return result;
  }

  // ==========================================================================
  // 20. Space Children Listing
  // ==========================================================================
  json get_space_children(const std::string& space_id,
                           int limit = 50,
                           const std::string& since = "",
                           const std::string& user_id = "") {
    auto children = store_.get_space_children(space_id);

    // Sort by order, then by name
    std::sort(children.begin(), children.end(),
      [](const SpaceNode& a, const SpaceNode& b) {
        if (a.order != b.order) return a.order < b.order;
        return a.name < b.name;
      });

    RoomPaginationToken pag = RoomPaginationToken::decode(since);
    int64_t start = pag.offset;

    json chunk = json::array();
    int64_t end = start;
    for (int64_t i = start; i < static_cast<int64_t>(children.size()) &&
         static_cast<int64_t>(chunk.size()) < limit; i++) {
      json node = children[i].to_tree_node();
      if (!user_id.empty()) {
        node["membership"] = check_membership(children[i].room_id, user_id);
      }
      chunk.push_back(node);
      end = i + 1;
    }

    json result;
    result["chunk"] = chunk;
    RoomPaginationToken next;
    if (end < static_cast<int64_t>(children.size())) {
      next.offset = end;
      result["next_batch"] = next.encode();
    } else {
      result["next_batch"] = "";
    }
    result["prev_batch"] = since;
    result["total_count_estimate"] = static_cast<int>(children.size());

    return result;
  }

  // ==========================================================================
  // 21. Space Parent Discovery
  // ==========================================================================
  json get_space_parents(const std::string& room_id) {
    auto parents = store_.get_space_parents(room_id);
    json result = json::array();
    for (const auto& p : parents) {
      auto entry = store_.get_room_entry(p);
      if (entry) {
        json parent;
        parent["room_id"] = p;
        if (!entry->name.empty()) parent["name"] = entry->name;
        if (!entry->canonical_alias.empty()) parent["canonical_alias"] = entry->canonical_alias;
        parent["num_joined_members"] = static_cast<int>(entry->num_joined_members);
        result.push_back(parent);
      }
    }
    return result;
  }

  // ==========================================================================
  // 22. Room Version Discovery
  // ==========================================================================
  json get_room_version(const std::string& room_id) {
    // Check store
    auto version = store_.get_room_version(room_id);
    if (version) {
      return json({{"room_version", *version}});
    }

    // Check DB
    if (db_) {
      StateStore state(*db_);
      std::string db_version = state.get_room_version_from_state(room_id);
      if (!db_version.empty()) {
        store_.set_room_version(room_id, db_version);
        return json({{"room_version", db_version}});
      }
    }

    // Default version
    return json({{"room_version", "1"}});
  }

  json set_room_version(const std::string& room_id, const std::string& version) {
    store_.set_room_version(room_id, version);
    store_.update_room_entry(room_id, [&](RoomDirectoryEntry& e) {
      e.room_version = version;
    });
    return json::object();
  }

  // ==========================================================================
  // 23. Federation Room Discovery
  // (GET /_matrix/federation/v1/publicRooms)
  // ==========================================================================
  json federation_list_public_rooms(int limit = 50,
                                     const std::string& since = "",
                                     const std::string& search_term = "",
                                     bool include_all_networks = false,
                                     bool third_party_instance_only = false,
                                     const std::string& network = "") {
    json result;
    if (limit <= 0) limit = 50;
    if (limit > 500) limit = 500;

    auto all_rooms = store_.get_published_rooms();

    // Only federatable rooms
    all_rooms.erase(std::remove_if(all_rooms.begin(), all_rooms.end(),
      [](const RoomDirectoryEntry& e) { return !e.is_federatable; }),
      all_rooms.end());

    // Filter network
    if (!network.empty() && !include_all_networks) {
      all_rooms.erase(std::remove_if(all_rooms.begin(), all_rooms.end(),
        [&](const RoomDirectoryEntry& e) { return e.network_id != network; }),
        all_rooms.end());
    }

    if (third_party_instance_only) {
      all_rooms.erase(std::remove_if(all_rooms.begin(), all_rooms.end(),
        [](const RoomDirectoryEntry& e) { return e.network_id.empty(); }),
        all_rooms.end());
    }

    // Search filter
    if (!search_term.empty()) {
      auto tokens = tokenize_search(search_term);
      all_rooms.erase(std::remove_if(all_rooms.begin(), all_rooms.end(),
        [&](const RoomDirectoryEntry& e) {
          return !matches_search(e.name, e.topic, e.canonical_alias, e.room_id, tokens);
        }), all_rooms.end());
    }

    // Sort
    std::sort(all_rooms.begin(), all_rooms.end(),
      [](const RoomDirectoryEntry& a, const RoomDirectoryEntry& b) {
        return a.num_joined_members > b.num_joined_members;
      });

    // Pagination
    RoomPaginationToken pag = RoomPaginationToken::decode(since);
    int64_t start = pag.offset;

    json chunk = json::array();
    int64_t end = start;
    for (int64_t i = start; i < static_cast<int64_t>(all_rooms.size()) &&
         static_cast<int64_t>(chunk.size()) < limit; i++) {
      chunk.push_back(all_rooms[i].to_federation_chunk());
      end = i + 1;
    }

    RoomPaginationToken next;
    if (end < static_cast<int64_t>(all_rooms.size())) {
      next.offset = end;
      result["next_batch"] = next.encode();
    } else {
      result["next_batch"] = "";
    }
    result["chunk"] = chunk;
    result["prev_batch"] = since;
    result["total_room_count_estimate"] = static_cast<int>(all_rooms.size());

    return result;
  }

  // ==========================================================================
  // 24. Federation Room Discovery with complex filter
  // ==========================================================================
  json federation_search_public_rooms(const json& filter_json,
                                       int limit = 50,
                                       const std::string& since = "") {
    json result;
    if (limit <= 0) limit = 50;
    if (limit > 500) limit = 500;

    DirectorySearchFilter filter = DirectorySearchFilter::from_json(filter_json);

    auto all_rooms = store_.get_published_rooms();

    // Only federatable
    all_rooms.erase(std::remove_if(all_rooms.begin(), all_rooms.end(),
      [](const RoomDirectoryEntry& e) { return !e.is_federatable; }),
      all_rooms.end());

    std::vector<RoomDirectoryEntry> filtered;
    for (const auto& entry : all_rooms) {
      if (filter.matches(entry)) {
        filtered.push_back(entry);
      }
    }

    sort_room_entries(filtered, filter.sort_order);

    RoomPaginationToken pag = RoomPaginationToken::decode(since);
    int64_t start = pag.offset;
    json chunk = json::array();
    int64_t end = start;
    for (int64_t i = start; i < static_cast<int64_t>(filtered.size()) &&
         static_cast<int64_t>(chunk.size()) < limit; i++) {
      chunk.push_back(filtered[i].to_federation_chunk());
      end = i + 1;
    }

    RoomPaginationToken next;
    if (end < static_cast<int64_t>(filtered.size())) {
      next.offset = end;
      result["next_batch"] = next.encode();
    } else {
      result["next_batch"] = "";
    }
    result["chunk"] = chunk;
    result["prev_batch"] = since;
    result["total_room_count_estimate"] = static_cast<int>(filtered.size());

    return result;
  }

  // ==========================================================================
  // 25. Room Statistics for Directory
  // ==========================================================================
  json get_room_statistics() {
    store_.compute_statistics();
    auto stats = store_.get_statistics();
    return stats.to_json();
  }

  json get_room_statistics_summary() {
    store_.compute_statistics();
    auto stats = store_.get_statistics();

    json result;
    result["total_rooms"] = static_cast<int>(stats.total_rooms);
    result["total_public_rooms"] = static_cast<int>(stats.total_public_rooms);
    result["total_spaces"] = static_cast<int>(stats.total_spaces);
    result["total_active_24h"] = static_cast<int>(stats.active_24h);
    result["total_active_7d"] = static_cast<int>(stats.active_7d);
    result["total_joined_members"] = static_cast<int>(stats.total_joined_members);
    result["avg_members_per_room"] = static_cast<int>(stats.avg_members_per_room);
    result["max_members_in_room"] = static_cast<int>(stats.max_members_in_room);
    result["last_updated"] = stats.last_updated_ts;
    return result;
  }

  // ==========================================================================
  // 26. Room Directory Pagination Helpers
  // ==========================================================================
  json get_directory_page(const std::string& sort_order = "members",
                           int limit = 50,
                           const std::string& since = "") {
    if (limit <= 0) limit = 50;
    if (limit > 500) limit = 500;

    auto all_rooms = store_.get_published_rooms();
    sort_room_entries(all_rooms, sort_order);

    RoomPaginationToken pag = RoomPaginationToken::decode(since);
    pag.sort_by = sort_order;

    json chunk = json::array();
    int64_t start = pag.offset;
    int64_t end = start;
    for (int64_t i = start; i < static_cast<int64_t>(all_rooms.size()) &&
         static_cast<int64_t>(chunk.size()) < limit; i++) {
      chunk.push_back(all_rooms[i].to_public_chunk());
      end = i + 1;
    }

    json result;
    result["chunk"] = chunk;
    result["total_room_count_estimate"] = static_cast<int>(all_rooms.size());

    if (end < static_cast<int64_t>(all_rooms.size())) {
      RoomPaginationToken next;
      next.offset = end;
      next.sort_by = sort_order;
      result["next_batch"] = next.encode();
    } else {
      result["next_batch"] = "";
    }
    result["prev_batch"] = since;

    return result;
  }

  // ==========================================================================
  // 27. Register / Update Room Entry (used by other handlers)
  // ==========================================================================
  void register_room(const std::string& room_id,
                      const std::string& name = "",
                      const std::string& topic = "",
                      const std::string& avatar_url = "",
                      const std::string& room_type = "",
                      const std::string& join_rule = "public",
                      bool is_encrypted = false,
                      bool is_federatable = true,
                      const std::string& room_version = "1",
                      const std::string& creator = "") {
    std::lock_guard lock(g_discovery_lock);

    auto existing = store_.get_room_entry(room_id);
    if (existing) {
      store_.update_room_entry(room_id, [&](RoomDirectoryEntry& e) {
        if (!name.empty()) e.name = name;
        if (!topic.empty()) e.topic = topic;
        if (!avatar_url.empty()) e.avatar_url = avatar_url;
        if (!room_type.empty()) e.room_type = room_type;
        if (!join_rule.empty()) e.join_rule = join_rule;
        e.is_encrypted = is_encrypted;
        e.is_federatable = is_federatable;
        if (!room_version.empty()) e.room_version = room_version;
        if (!creator.empty()) e.creator = creator;
        e.last_active_ts = now_ms();
      });
    } else {
      RoomDirectoryEntry entry;
      entry.room_id = room_id;
      entry.name = name;
      entry.topic = topic;
      entry.avatar_url = avatar_url;
      entry.room_type = room_type;
      entry.join_rule = join_rule;
      entry.is_encrypted = is_encrypted;
      entry.is_federatable = is_federatable;
      entry.room_version = room_version;
      entry.creator = creator;
      entry.last_active_ts = now_ms();
      entry.created_ts = now_ms();
      entry.visibility = "private";
      store_.add_room_entry(entry);
    }
  }

  void update_room_member_count(const std::string& room_id,
                                 int64_t joined_count,
                                 int64_t invited_count = 0) {
    store_.update_room_entry(room_id, [&](RoomDirectoryEntry& e) {
      e.num_joined_members = joined_count;
      e.num_invited_members = invited_count;
    });
  }

  void update_room_name(const std::string& room_id, const std::string& name) {
    store_.update_room_entry(room_id, [&](RoomDirectoryEntry& e) {
      e.name = name;
    });
  }

  void update_room_topic(const std::string& room_id, const std::string& topic) {
    store_.update_room_entry(room_id, [&](RoomDirectoryEntry& e) {
      e.topic = topic;
    });
  }

  void update_room_avatar(const std::string& room_id, const std::string& avatar_url) {
    store_.update_room_entry(room_id, [&](RoomDirectoryEntry& e) {
      e.avatar_url = avatar_url;
    });
  }

  void update_room_activity(const std::string& room_id) {
    store_.update_room_entry(room_id, [&](RoomDirectoryEntry& e) {
      e.last_active_ts = now_ms();
    });
  }

  void update_room_encryption(const std::string& room_id, bool encrypted) {
    store_.update_room_entry(room_id, [&](RoomDirectoryEntry& e) {
      e.is_encrypted = encrypted;
    });
  }

  void set_room_history_visibility(const std::string& room_id,
                                     const std::string& visibility) {
    store_.update_room_entry(room_id, [&](RoomDirectoryEntry& e) {
      e.world_readable = (visibility == "world_readable") ? "world_readable" : "";
    });
  }

  void set_room_guest_access(const std::string& room_id,
                               const std::string& guest_access) {
    store_.update_room_entry(room_id, [&](RoomDirectoryEntry& e) {
      e.guest_can_join = guest_access;
    });
  }

  void set_room_join_rules(const std::string& room_id,
                             const std::string& join_rule) {
    store_.update_room_entry(room_id, [&](RoomDirectoryEntry& e) {
      e.join_rule = join_rule;
    });
  }

  // ==========================================================================
  // 28. Third-Party Protocol Room Management
  // ==========================================================================
  void register_third_party_room(const std::string& room_id,
                                   const std::string& network_id,
                                   const std::string& protocol_id,
                                   const json& tp_data = json::object()) {
    store_.update_room_entry(room_id, [&](RoomDirectoryEntry& e) {
      e.network_id = network_id;
      e.protocol_id = protocol_id;
      e.third_party_data = tp_data;
    });
  }

  void register_third_party_instance(const ThirdPartyInstance& instance) {
    store_.add_third_party_instance(instance);
  }

  void register_third_party_location(const ThirdPartyLocation& location) {
    store_.add_third_party_location(location);
  }

  void register_third_party_user(const ThirdPartyUser& user) {
    store_.add_third_party_user(user);
  }

  // ==========================================================================
  // 29. Space Room Management
  // ==========================================================================
  void register_space(const std::string& space_id,
                       const std::string& name = "",
                       const std::string& topic = "") {
    RoomDirectoryEntry entry;
    entry.room_id = space_id;
    entry.name = name;
    entry.topic = topic;
    entry.room_type = "m.space";
    entry.created_ts = now_ms();
    entry.last_active_ts = now_ms();
    entry.visibility = "private";
    store_.add_room_entry(entry);
  }

  void add_child_to_space(const std::string& space_id,
                           const SpaceNode& child) {
    store_.add_space_child(space_id, child);
    store_.add_space_parent(child.room_id, space_id);
  }

  void remove_child_from_space(const std::string& space_id,
                                 const std::string& child_room_id) {
    auto existing = store_.get_space_children(space_id);
    existing.erase(std::remove_if(existing.begin(), existing.end(),
      [&](const SpaceNode& n) { return n.room_id == child_room_id; }),
      existing.end());
    store_.set_space_children(space_id, existing);
  }

  void set_space_suggested(const std::string& space_id,
                             const std::string& child_room_id,
                             bool suggested,
                             const std::string& reason = "",
                             bool auto_join = false,
                             int order = 0) {
    auto children = store_.get_space_children(space_id);
    for (auto& child : children) {
      if (child.room_id == child_room_id) {
        child.is_suggested = suggested;
        child.suggested_reason = reason;
        child.is_auto_join = auto_join;
        child.order = order;
        break;
      }
    }
    store_.set_space_children(space_id, children);
  }

  // ==========================================================================
  // 30. Batch Room Registration for bulk import
  // ==========================================================================
  void bulk_register_rooms(const std::vector<RoomDirectoryEntry>& rooms) {
    for (const auto& room : rooms) {
      store_.add_room_entry(room);
    }
    store_.compute_statistics();
  }

  // ==========================================================================
  // 31. Clear all data
  // ==========================================================================
  void clear_all() {
    // The store will be replaced on next usage
    // We rebuild a fresh one
    store_ = RoomDiscoveryStore();
    preview_cache_.clear();
    space_cache_.clear();
    init_default_protocols();
  }

  // ==========================================================================
  // 32. Get raw room entry (for internal use)
  // ==========================================================================
  std::optional<RoomDirectoryEntry> get_room_entry(const std::string& room_id) {
    return store_.get_room_entry(room_id);
  }

  // ==========================================================================
  // 33. List all rooms (for admin)
  // ==========================================================================
  json list_all_rooms(int limit = 100, const std::string& since = "") {
    if (limit <= 0) limit = 100;
    if (limit > 1000) limit = 1000;

    auto all_rooms = store_.get_all_rooms();
    sort_room_entries(all_rooms, "recency");

    RoomPaginationToken pag = RoomPaginationToken::decode(since);
    json chunk = json::array();
    int64_t start = pag.offset;
    int64_t end = start;

    for (int64_t i = start; i < static_cast<int64_t>(all_rooms.size()) &&
         static_cast<int64_t>(chunk.size()) < limit; i++) {
      chunk.push_back(all_rooms[i].to_full_summary());
      end = i + 1;
    }

    json result;
    result["chunk"] = chunk;
    result["total_room_count"] = static_cast<int>(all_rooms.size());
    if (end < static_cast<int64_t>(all_rooms.size())) {
      RoomPaginationToken next;
      next.offset = end;
      result["next_batch"] = next.encode();
    } else {
      result["next_batch"] = "";
    }
    result["prev_batch"] = since;
    return result;
  }

  // ==========================================================================
  // 34. Check if a room exists in the directory
  // ==========================================================================
  bool room_exists(const std::string& room_id) {
    auto entry = store_.get_room_entry(room_id);
    return entry.has_value();
  }

  // ==========================================================================
  // 35. Get room count
  // ==========================================================================
  int64_t get_total_room_count() {
    auto all = store_.get_all_rooms();
    return static_cast<int64_t>(all.size());
  }

  int64_t get_published_room_count() {
    auto all = store_.get_published_rooms();
    return static_cast<int64_t>(all.size());
  }

private:
  DatabasePool* db_{nullptr};
  RoomDiscoveryStore store_;
  DiscoveryLRUCache<std::string, json> preview_cache_{5000};
  DiscoveryLRUCache<std::string, json> space_cache_{1000};

  // ==========================================================================
  // Private methods
  // ==========================================================================

  void init_default_protocols() {
    ThirdPartyProtocolConfig irc;
    irc.user_fields = "network,channel,nickname";
    irc.location_fields = "network,channel";
    irc.icon = "mxc://localhost/irc_icon";
    irc.field_types = {"network", "channel", "nickname"};
    irc.instances = {"freenode", "oftc", "libera", "espernet"};
    store_.register_protocol("irc", irc);

    ThirdPartyProtocolConfig gitter;
    gitter.user_fields = "room";
    gitter.location_fields = "room";
    gitter.icon = "mxc://localhost/gitter_icon";
    gitter.field_types = {"room"};
    gitter.instances = {};
    store_.register_protocol("gitter", gitter);

    ThirdPartyProtocolConfig discord;
    discord.user_fields = "guild,channel";
    discord.location_fields = "guild,channel";
    discord.icon = "mxc://localhost/discord_icon";
    discord.field_types = {"guild", "channel"};
    discord.instances = {};
    store_.register_protocol("discord", discord);

    ThirdPartyProtocolConfig telegram;
    telegram.user_fields = "chat_id";
    telegram.location_fields = "chat_id";
    telegram.icon = "mxc://localhost/telegram_icon";
    telegram.field_types = {"chat_id"};
    telegram.instances = {};
    store_.register_protocol("telegram", telegram);

    ThirdPartyProtocolConfig slack;
    slack.user_fields = "team,channel";
    slack.location_fields = "team,channel";
    slack.icon = "mxc://localhost/slack_icon";
    slack.field_types = {"team", "channel"};
    slack.instances = {};
    store_.register_protocol("slack", slack);

    ThirdPartyProtocolConfig xmpp;
    xmpp.user_fields = "room_jid";
    xmpp.location_fields = "room_jid";
    xmpp.icon = "mxc://localhost/xmpp_icon";
    xmpp.field_types = {"room_jid"};
    xmpp.instances = {};
    store_.register_protocol("xmpp", xmpp);
  }

  void init_bootstrap_rooms() {
    // Seed some example rooms for testing
    {
      RoomDirectoryEntry entry;
      entry.room_id = "!welcome:localhost";
      entry.name = "Welcome";
      entry.topic = "Welcome to the Matrix server! Introduce yourself here.";
      entry.num_joined_members = 42;
      entry.room_type = "";
      entry.join_rule = "public";
      entry.world_readable = "world_readable";
      entry.guest_can_join = "can_join";
      entry.canonical_alias = "#welcome:localhost";
      entry.is_published = true;
      entry.visibility = "public";
      entry.room_version = "10";
      entry.is_federatable = true;
      entry.last_active_ts = now_ms();
      entry.created_ts = now_ms() - 86400000;
      store_.add_room_entry(entry);
      store_.add_alias("#welcome:localhost", "!welcome:localhost");
    }

    {
      RoomDirectoryEntry entry;
      entry.room_id = "!general:localhost";
      entry.name = "General Discussion";
      entry.topic = "General chat about anything and everything.";
      entry.num_joined_members = 128;
      entry.join_rule = "public";
      entry.world_readable = "world_readable";
      entry.guest_can_join = "can_join";
      entry.canonical_alias = "#general:localhost";
      entry.is_published = true;
      entry.visibility = "public";
      entry.room_version = "10";
      entry.is_federatable = true;
      entry.last_active_ts = now_ms() - 3600000;
      entry.created_ts = now_ms() - 86400000 * 30;
      store_.add_room_entry(entry);
      store_.add_alias("#general:localhost", "!general:localhost");
    }

    {
      RoomDirectoryEntry entry;
      entry.room_id = "!dev:localhost";
      entry.name = "Development";
      entry.topic = "Discuss Matrix development, APIs, and client building.";
      entry.num_joined_members = 85;
      entry.join_rule = "public";
      entry.world_readable = "";
      entry.guest_can_join = "";
      entry.canonical_alias = "#dev:localhost";
      entry.is_published = true;
      entry.visibility = "public";
      entry.is_encrypted = true;
      entry.room_version = "10";
      entry.is_federatable = true;
      entry.last_active_ts = now_ms() - 7200000;
      entry.created_ts = now_ms() - 86400000 * 60;
      store_.add_room_entry(entry);
      store_.add_alias("#dev:localhost", "!dev:localhost");
    }

    {
      RoomDirectoryEntry entry;
      entry.room_id = "!random:localhost";
      entry.name = "Random";
      entry.topic = "Off-topic chat, memes, and fun stuff.";
      entry.num_joined_members = 201;
      entry.join_rule = "public";
      entry.world_readable = "";
      entry.guest_can_join = "";
      entry.is_published = true;
      entry.visibility = "public";
      entry.room_version = "9";
      entry.is_federatable = true;
      entry.last_active_ts = now_ms() - 1800000;
      entry.created_ts = now_ms() - 86400000 * 90;
      store_.add_room_entry(entry);
      store_.add_alias("#random:localhost", "!random:localhost");
    }

    {
      RoomDirectoryEntry entry;
      entry.room_id = "!support:localhost";
      entry.name = "Support";
      entry.topic = "Get help with Matrix, clients, and server issues.";
      entry.num_joined_members = 15;
      entry.join_rule = "public";
      entry.world_readable = "world_readable";
      entry.guest_can_join = "can_join";
      entry.canonical_alias = "#support:localhost";
      entry.is_published = true;
      entry.visibility = "public";
      entry.room_version = "10";
      entry.is_federatable = true;
      entry.last_active_ts = now_ms() - 86400000;
      entry.created_ts = now_ms() - 86400000 * 120;
      store_.add_room_entry(entry);
      store_.add_alias("#support:localhost", "!support:localhost");
    }

    // Space rooms
    {
      RoomDirectoryEntry entry;
      entry.room_id = "!community:localhost";
      entry.name = "Matrix Community Space";
      entry.topic = "The main community space for this Matrix server.";
      entry.num_joined_members = 256;
      entry.room_type = "m.space";
      entry.join_rule = "public";
      entry.world_readable = "world_readable";
      entry.guest_can_join = "can_join";
      entry.canonical_alias = "#community:localhost";
      entry.is_published = true;
      entry.visibility = "public";
      entry.room_version = "10";
      entry.is_federatable = true;
      entry.last_active_ts = now_ms();
      entry.created_ts = now_ms() - 86400000 * 45;
      store_.add_room_entry(entry);
      store_.add_alias("#community:localhost", "!community:localhost");

      // Add children to the space
      SpaceNode child1; child1.room_id = "!welcome:localhost"; child1.name = "Welcome";
      child1.join_rule = "public"; child1.num_joined_members = 42;
      child1.is_suggested = true; child1.order = 0;
      store_.add_space_child("!community:localhost", child1);
      store_.add_space_parent("!welcome:localhost", "!community:localhost");

      SpaceNode child2; child2.room_id = "!general:localhost"; child2.name = "General Discussion";
      child2.join_rule = "public"; child2.num_joined_members = 128;
      child2.is_suggested = true; child2.order = 1;
      store_.add_space_child("!community:localhost", child2);
      store_.add_space_parent("!general:localhost", "!community:localhost");

      SpaceNode child3; child3.room_id = "!dev:localhost"; child3.name = "Development";
      child3.join_rule = "public"; child3.num_joined_members = 85;
      child3.is_suggested = true; child3.order = 2;
      store_.add_space_child("!community:localhost", child3);
      store_.add_space_parent("!dev:localhost", "!community:localhost");

      SpaceNode child4; child4.room_id = "!random:localhost"; child4.name = "Random";
      child4.join_rule = "public"; child4.num_joined_members = 201; child4.order = 3;
      store_.add_space_child("!community:localhost", child4);
    }

    // Third-party bridge rooms
    {
      RoomDirectoryEntry entry;
      entry.room_id = "!irc_freenode:localhost";
      entry.name = "#matrix on Freenode";
      entry.topic = "Matrix IRC bridge - #matrix channel on Freenode";
      entry.num_joined_members = 310;
      entry.join_rule = "public";
      entry.is_published = true;
      entry.visibility = "public";
      entry.network_id = "freenode";
      entry.protocol_id = "irc";
      entry.room_version = "10";
      entry.is_federatable = true;
      entry.last_active_ts = now_ms();
      entry.created_ts = now_ms() - 86400000 * 200;
      store_.add_room_entry(entry);
    }

    {
      RoomDirectoryEntry entry;
      entry.room_id = "!discord_general:localhost";
      entry.name = "Discord General";
      entry.topic = "General chat bridged from Discord";
      entry.num_joined_members = 542;
      entry.join_rule = "public";
      entry.is_published = true;
      entry.visibility = "public";
      entry.network_id = "myguild";
      entry.protocol_id = "discord";
      entry.room_version = "10";
      entry.is_federatable = true;
      entry.last_active_ts = now_ms() - 300000;
      entry.created_ts = now_ms() - 86400000 * 100;
      store_.add_room_entry(entry);
    }

    // Private rooms
    {
      RoomDirectoryEntry entry;
      entry.room_id = "!private_team:localhost";
      entry.name = "Private Team Room";
      entry.topic = "Confidential team discussions";
      entry.num_joined_members = 8;
      entry.join_rule = "invite";
      entry.is_encrypted = true;
      entry.room_version = "10";
      entry.is_federatable = true;
      entry.last_active_ts = now_ms() - 3600000;
      entry.created_ts = now_ms() - 86400000 * 15;
      store_.add_room_entry(entry);
    }

    // Additional rooms for pagination testing
    for (int i = 1; i <= 40; i++) {
      std::string rid = "!testroom" + std::to_string(i) + ":localhost";
      std::string alias = "#testroom" + std::to_string(i) + ":localhost";
      RoomDirectoryEntry entry;
      entry.room_id = rid;
      entry.name = "Test Room " + std::to_string(i);
      entry.topic = "Automated test room #" + std::to_string(i) + " for pagination testing.";
      entry.num_joined_members = 10 + (i % 20);
      entry.join_rule = (i % 3 == 0) ? "invite" : "public";
      entry.is_published = (i % 3 != 0);
      entry.visibility = (i % 3 == 0) ? "private" : "public";
      entry.canonical_alias = entry.is_published ? alias : "";
      entry.room_version = (i % 5 == 0) ? "9" : "10";
      entry.is_federatable = (i % 7 != 0);
      entry.is_encrypted = (i % 4 == 0);
      entry.last_active_ts = now_ms() - (i * 3600000);
      entry.created_ts = now_ms() - (i * 86400000);
      store_.add_room_entry(entry);
      if (entry.is_published) {
        store_.add_alias(alias, rid);
      }
    }
  }

  void sort_room_entries(std::vector<RoomDirectoryEntry>& entries,
                          const std::string& sort_order) {
    if (sort_order == "name") {
      std::sort(entries.begin(), entries.end(),
        [](const RoomDirectoryEntry& a, const RoomDirectoryEntry& b) {
          std::string na = a.name;
          std::string nb = b.name;
          std::transform(na.begin(), na.end(), na.begin(),
            [](unsigned char c) { return std::tolower(c); });
          std::transform(nb.begin(), nb.end(), nb.begin(),
            [](unsigned char c) { return std::tolower(c); });
          return na < nb;
        });
    } else if (sort_order == "recency") {
      std::sort(entries.begin(), entries.end(),
        [](const RoomDirectoryEntry& a, const RoomDirectoryEntry& b) {
          return a.last_active_ts > b.last_active_ts;
        });
    } else {
      // Default: by member count, then recency
      std::sort(entries.begin(), entries.end(),
        [](const RoomDirectoryEntry& a, const RoomDirectoryEntry& b) {
          if (a.num_joined_members != b.num_joined_members)
            return a.num_joined_members > b.num_joined_members;
          return a.last_active_ts > b.last_active_ts;
        });
    }
  }

  void traverse_space(const std::string& space_id,
                       json& children_json,
                       int max_depth,
                       int current_depth,
                       int limit,
                       std::unordered_set<std::string>& visited,
                       bool suggested_only) {
    if (current_depth >= max_depth) return;
    if (visited.count(space_id)) return;
    visited.insert(space_id);

    auto children = store_.get_space_children(space_id);
    int count = 0;
    for (const auto& child : children) {
      if (count >= limit) break;
      if (suggested_only && !child.is_suggested) continue;

      json node = child.to_tree_node();
      node["depth"] = current_depth + 1;

      // Recurse into child spaces
      if (child.room_type == "m.space") {
        json grand_children = json::array();
        traverse_space(child.room_id, grand_children, max_depth,
                       current_depth + 1, limit, visited, suggested_only);
        node["children_state"] = grand_children;
      }

      children_json.push_back(node);
      count++;
    }
  }

  RoomPreviewData load_preview_from_db(const std::string& room_id,
                                         const std::string& user_id) {
    RoomPreviewData preview;
    preview.room_id = room_id;

    if (!db_) return preview;

    try {
      // Load state events from DB
      StateStore state(*db_);
      auto create_ev = state.get_create_event(room_id);
      if (create_ev) {
        preview.room_type = safe_str(*create_ev, "type", "");
        preview.creator = safe_str(*create_ev, "creator", "");
        preview.room_version = safe_str(*create_ev, "room_version", "1");
      }

      // Name
      auto name_event = state.get_current_state_event(room_id, "m.room.name");
      if (name_event) {
        try {
          json nev = json::parse(*name_event);
          if (nev.contains("content") && nev["content"].contains("name")) {
            preview.name = nev["content"]["name"].get<std::string>();
          }
        } catch (...) {}
      }

      // Topic
      auto topic_event = state.get_current_state_event(room_id, "m.room.topic");
      if (topic_event) {
        try {
          json tev = json::parse(*topic_event);
          if (tev.contains("content") && tev["content"].contains("topic")) {
            preview.topic = tev["content"]["topic"].get<std::string>();
          }
        } catch (...) {}
      }

      // Avatar
      auto avatar_event = state.get_current_state_event(room_id, "m.room.avatar");
      if (avatar_event) {
        try {
          json aev = json::parse(*avatar_event);
          if (aev.contains("content") && aev["content"].contains("url")) {
            preview.avatar_url = aev["content"]["url"].get<std::string>();
          }
        } catch (...) {}
      }

      // Canonical alias
      auto alias_event = state.get_current_state_event(room_id, "m.room.canonical_alias");
      if (alias_event) {
        try {
          json alev = json::parse(*alias_event);
          if (alev.contains("content") && alev["content"].contains("alias")) {
            preview.canonical_alias = alev["content"]["alias"].get<std::string>();
          }
          if (alev.contains("content") && alev["content"].contains("alt_aliases")) {
            for (const auto& a : alev["content"]["alt_aliases"]) {
              if (a.is_string()) preview.alt_aliases.push_back(a.get<std::string>());
            }
          }
        } catch (...) {}
      }

      // History visibility
      auto hv_event = state.get_current_state_event(room_id, "m.room.history_visibility");
      if (hv_event) {
        try {
          json hvev = json::parse(*hv_event);
          if (hvev.contains("content") && hvev["content"].contains("history_visibility")) {
            preview.history_visibility = hvev["content"]["history_visibility"].get<std::string>();
            preview.world_readable = (preview.history_visibility == "world_readable");
          }
        } catch (...) {}
      }

      // Guest access
      auto guest_event = state.get_current_state_event(room_id, "m.room.guest_access");
      if (guest_event) {
        try {
          json gev = json::parse(*guest_event);
          if (gev.contains("content") && gev["content"].contains("guest_access")) {
            preview.guest_can_join = (gev["content"]["guest_access"].get<std::string>() == "can_join");
          }
        } catch (...) {}
      }

      // Join rules
      auto jr_event = state.get_current_state_event(room_id, "m.room.join_rules");
      if (jr_event) {
        try {
          json jrev = json::parse(*jr_event);
          if (jrev.contains("content") && jrev["content"].contains("join_rule")) {
            preview.join_rule = jrev["content"]["join_rule"].get<std::string>();
          }
        } catch (...) {}
      }

      // Encryption
      auto enc_event = state.get_current_state_event(room_id, "m.room.encryption");
      if (enc_event) {
        try {
          json encev = json::parse(*enc_event);
          if (encev.contains("content") && encev["content"].contains("algorithm")) {
            preview.is_encrypted = true;
          }
        } catch (...) {}
      }

      // Member counts from room member store
      RoomMemberWorkerStore member_store(*db_);
      auto summary = member_store.get_room_member_summary(room_id);
      preview.num_joined_members = summary.joined_members;
      preview.num_invited_members = summary.invited_members;

      // Heroes
      json hero_arr = json::array();
      for (const auto& hero_id : summary.heroes) {
        json h;
        h["user_id"] = hero_id;
        // Try to get display name and avatar
        ProfileStore profile(*db_);
        auto display_name = profile.get_display_name(hero_id);
        auto avatar = profile.get_avatar_url(hero_id);
        if (display_name) h["display_name"] = *display_name;
        if (avatar) h["avatar_url"] = *avatar;
        hero_arr.push_back(h);
      }
      preview.heroes = hero_arr;

      // Room version
      std::string version = state.get_room_version_from_state(room_id);
      if (!version.empty()) preview.room_version = version;

      // Space detection
      preview.is_space = (preview.room_type == "m.space");

    } catch (...) {
      // If DB loading fails, fall back to store data
    }

    return preview;
  }

  RoomPreviewData build_preview_from_store(const std::string& room_id,
                                              const std::string& user_id) {
    RoomPreviewData preview;
    preview.room_id = room_id;

    auto entry = store_.get_room_entry(room_id);
    if (entry) {
      preview.name = entry->name;
      preview.topic = entry->topic;
      preview.avatar_url = entry->avatar_url;
      preview.canonical_alias = entry->canonical_alias;
      preview.alt_aliases = entry->aliases;
      preview.num_joined_members = entry->num_joined_members;
      preview.num_invited_members = entry->num_invited_members;
      preview.room_type = entry->room_type;
      preview.world_readable = (entry->world_readable == "world_readable");
      preview.guest_can_join = (entry->guest_can_join == "can_join");
      preview.is_encrypted = entry->is_encrypted;
      preview.join_rule = entry->join_rule;
      preview.room_version = entry->room_version;
      preview.creator = entry->creator;
      preview.network_id = entry->network_id;
      preview.protocol_id = entry->protocol_id;
      preview.is_space = (entry->room_type == "m.space");
    }

    // Add default name if empty
    if (preview.name.empty()) {
      preview.name = "Room Preview";
    }

    return preview;
  }

  std::string check_membership(const std::string& room_id,
                                 const std::string& user_id) {
    if (user_id.empty()) return "leave";

    if (db_) {
      try {
        RoomMemberWorkerStore members(*db_);
        auto member = members.get_member(room_id, user_id);
        if (member) return member->membership;
      } catch (...) {}
    }

    return "leave";
  }
};

// ============================================================================
// RoomDiscoveryAPI - Public API class wrapping RoomDiscoveryHandler
// ============================================================================

class RoomDiscoveryAPI {
public:
  RoomDiscoveryAPI() : handler_() {}
  explicit RoomDiscoveryAPI(DatabasePool& db) : handler_(db) {}

  // --- Public Room Listing ---
  json list_public_rooms(const json& params = json::object()) {
    std::string server = safe_str(params, "server", "");
    int limit = static_cast<int>(safe_int(params, "limit", 50));
    std::string since = safe_str(params, "since", "");
    std::string term = safe_str(params, "search_term", "");
    std::string network = safe_str(params, "network", "");
    bool all_nets = safe_bool(params, "include_all_networks", false);
    bool tpi_only = safe_bool(params, "third_party_instance_only", false);

    return handler_.list_public_rooms(server, limit, since, term, network,
                                       all_nets, tpi_only);
  }

  json search_public_rooms(const json& body) {
    json filter;
    if (body.contains("filter")) filter = body["filter"];
    int limit = static_cast<int>(safe_int(body, "limit", 50));
    std::string since = safe_str(body, "since", "");
    std::string server = safe_str(body, "server", "");
    return handler_.search_public_rooms(filter, limit, since, server);
  }

  // --- Room Preview ---
  json get_room_preview(const std::string& room_id,
                         const std::string& user_id = "",
                         const json& via = json::array()) {
    return handler_.get_room_preview(room_id, user_id, via);
  }

  json get_room_preview_unauthenticated(const std::string& room_id) {
    return handler_.get_room_preview_unauthenticated(room_id);
  }

  // --- Alias Management ---
  json resolve_alias(const std::string& alias) {
    return handler_.discover_room_by_alias(alias);
  }

  json create_alias(const std::string& alias, const std::string& room_id,
                     const std::string& user_id = "",
                     const std::vector<std::string>& servers = {}) {
    return handler_.create_alias(alias, room_id, user_id, servers);
  }

  json delete_alias(const std::string& alias, const std::string& user_id = "") {
    return handler_.delete_alias(alias, user_id);
  }

  json get_room_local_aliases(const std::string& room_id) {
    return handler_.get_room_local_aliases(room_id);
  }

  // --- Third-Party Protocols ---
  json get_third_party_protocols() {
    return handler_.list_third_party_protocols();
  }

  json get_third_party_protocol(const std::string& protocol) {
    return handler_.get_third_party_protocol(protocol);
  }

  json query_third_party_user(const std::string& protocol,
                                const json& fields = json::object()) {
    return handler_.query_third_party_user(protocol, fields);
  }

  json query_third_party_location(const std::string& protocol,
                                    const json& fields = json::object()) {
    return handler_.query_third_party_location(protocol, fields);
  }

  // --- Canonical Alias ---
  json get_canonical_alias(const std::string& room_id) {
    return handler_.get_canonical_alias(room_id);
  }

  json set_canonical_alias(const std::string& room_id,
                            const std::string& alias,
                            const std::string& user_id = "") {
    return handler_.set_canonical_alias(room_id, alias, user_id);
  }

  // --- Alt Aliases ---
  json get_alt_aliases(const std::string& room_id) {
    return handler_.get_alt_aliases(room_id);
  }

  json add_alt_alias(const std::string& room_id, const std::string& alias,
                      const std::string& user_id = "") {
    return handler_.add_alt_alias(room_id, alias, user_id);
  }

  json remove_alt_alias(const std::string& room_id, const std::string& alias,
                         const std::string& user_id = "") {
    return handler_.remove_alt_alias(room_id, alias, user_id);
  }

  // --- Visibility ---
  json get_room_visibility(const std::string& room_id) {
    return handler_.get_room_visibility(room_id);
  }

  json set_room_visibility(const std::string& room_id,
                            const std::string& visibility,
                            const std::string& user_id = "") {
    return handler_.set_room_visibility(room_id, visibility, user_id);
  }

  // --- Publishing ---
  json publish_room(const std::string& room_id, const std::string& user_id = "") {
    return handler_.publish_room(room_id, user_id);
  }

  json unpublish_room(const std::string& room_id, const std::string& user_id = "") {
    return handler_.unpublish_room(room_id, user_id);
  }

  // --- Unauthenticated Summary ---
  json get_room_summary_unauthenticated(const std::string& room_id) {
    return handler_.get_room_summary_unauthenticated(room_id);
  }

  // --- Spaces ---
  json discover_space_hierarchy(const std::string& space_id,
                                 int max_depth = 3,
                                 int limit = 50,
                                 const std::string& user_id = "",
                                 bool suggested_only = false) {
    return handler_.discover_space_hierarchy(space_id, max_depth, limit,
                                              user_id, suggested_only);
  }

  json get_space_children(const std::string& space_id,
                           int limit = 50,
                           const std::string& since = "",
                           const std::string& user_id = "") {
    return handler_.get_space_children(space_id, limit, since, user_id);
  }

  json get_space_parents(const std::string& room_id) {
    return handler_.get_space_parents(room_id);
  }

  // --- Room Version ---
  json get_room_version(const std::string& room_id) {
    return handler_.get_room_version(room_id);
  }

  json set_room_version(const std::string& room_id, const std::string& version) {
    return handler_.set_room_version(room_id, version);
  }

  // --- Federation ---
  json federation_list_public_rooms(const json& params = json::object()) {
    int limit = static_cast<int>(safe_int(params, "limit", 50));
    std::string since = safe_str(params, "since", "");
    std::string term = safe_str(params, "search_term", "");
    bool all_nets = safe_bool(params, "include_all_networks", false);
    bool tpi_only = safe_bool(params, "third_party_instance_only", false);
    std::string network = safe_str(params, "network", "");
    return handler_.federation_list_public_rooms(limit, since, term,
                                                   all_nets, tpi_only, network);
  }

  json federation_search_public_rooms(const json& body) {
    json filter;
    if (body.contains("filter")) filter = body["filter"];
    int limit = static_cast<int>(safe_int(body, "limit", 50));
    std::string since = safe_str(body, "since", "");
    return handler_.federation_search_public_rooms(filter, limit, since);
  }

  // --- Statistics ---
  json get_room_statistics() {
    return handler_.get_room_statistics();
  }

  json get_room_statistics_summary() {
    return handler_.get_room_statistics_summary();
  }

  // --- Directory pagination ---
  json get_directory_page(const std::string& sort_order = "members",
                           int limit = 50,
                           const std::string& since = "") {
    return handler_.get_directory_page(sort_order, limit, since);
  }

  // --- Room management ---
  void register_room(const std::string& room_id, const std::string& name = "",
                      const std::string& topic = "", const std::string& avatar = "",
                      const std::string& room_type = "",
                      const std::string& join_rule = "public",
                      bool encrypted = false, bool federatable = true,
                      const std::string& version = "1",
                      const std::string& creator = "") {
    handler_.register_room(room_id, name, topic, avatar, room_type,
                            join_rule, encrypted, federatable, version, creator);
  }

  void update_room_name(const std::string& room_id, const std::string& name) {
    handler_.update_room_name(room_id, name);
  }

  void update_room_topic(const std::string& room_id, const std::string& topic) {
    handler_.update_room_topic(room_id, topic);
  }

  void update_room_avatar(const std::string& room_id, const std::string& avatar) {
    handler_.update_room_avatar(room_id, avatar);
  }

  void update_member_count(const std::string& room_id, int64_t count) {
    handler_.update_room_member_count(room_id, count);
  }

  void update_room_activity(const std::string& room_id) {
    handler_.update_room_activity(room_id);
  }

  void set_room_history_visibility(const std::string& room_id,
                                     const std::string& vis) {
    handler_.set_room_history_visibility(room_id, vis);
  }

  void set_room_guest_access(const std::string& room_id,
                               const std::string& access) {
    handler_.set_room_guest_access(room_id, access);
  }

  void set_room_join_rules(const std::string& room_id,
                             const std::string& rules) {
    handler_.set_room_join_rules(room_id, rules);
  }

  void register_third_party_room(const std::string& room_id,
                                   const std::string& network,
                                   const std::string& protocol,
                                   const json& data = json::object()) {
    handler_.register_third_party_room(room_id, network, protocol, data);
  }

  void register_space(const std::string& space_id,
                       const std::string& name = "",
                       const std::string& topic = "") {
    handler_.register_space(space_id, name, topic);
  }

  void add_child_to_space(const std::string& space_id,
                           const std::string& child_room_id,
                           const std::string& child_name = "",
                           const std::string& child_type = "",
                           const std::string& join_rule = "",
                           int64_t member_count = 0,
                           bool suggested = false,
                           const std::string& reason = "",
                           bool auto_join = false,
                           int order = 0) {
    SpaceNode child;
    child.room_id = child_room_id;
    child.name = child_name;
    child.room_type = child_type;
    child.join_rule = join_rule;
    child.num_joined_members = member_count;
    child.is_suggested = suggested;
    child.suggested_reason = reason;
    child.is_auto_join = auto_join;
    child.order = order;
    handler_.add_child_to_space(space_id, child);
  }

  void remove_child_from_space(const std::string& space_id,
                                 const std::string& child_room_id) {
    handler_.remove_child_from_space(space_id, child_room_id);
  }

  void clear_all() {
    handler_.clear_all();
  }

  bool room_exists(const std::string& room_id) {
    return handler_.room_exists(room_id);
  }

private:
  RoomDiscoveryHandler handler_;
};

// ============================================================================
// Global instance and factory function
// ============================================================================

static std::unique_ptr<RoomDiscoveryAPI> g_discovery_api;
static std::mutex g_discovery_api_mutex;

RoomDiscoveryAPI& get_discovery_api() {
  std::lock_guard lock(g_discovery_api_mutex);
  if (!g_discovery_api) {
    g_discovery_api = std::make_unique<RoomDiscoveryAPI>();
  }
  return *g_discovery_api;
}

RoomDiscoveryAPI& get_discovery_api(DatabasePool& db) {
  std::lock_guard lock(g_discovery_api_mutex);
  if (!g_discovery_api) {
    g_discovery_api = std::make_unique<RoomDiscoveryAPI>(db);
  }
  return *g_discovery_api;
}

void destroy_discovery_api() {
  std::lock_guard lock(g_discovery_api_mutex);
  g_discovery_api.reset();
}

// ============================================================================
// RoomSuggestionEngine - Room recommendation and suggestion system
// ============================================================================

class RoomSuggestionEngine {
public:
  RoomSuggestionEngine() = default;
  explicit RoomSuggestionEngine(RoomDiscoveryHandler& handler) : handler_(&handler) {}

  struct RoomSuggestion {
    std::string room_id;
    std::string name;
    std::string topic;
    std::string reason;
    double score{0.0};
    int member_count{0};
    std::vector<std::string> shared_members;
    bool is_encrypted{false};
    std::string room_type;
    int64_t last_active_ts{0};

    json to_json() const {
      json j;
      j["room_id"] = room_id;
      if (!name.empty()) j["name"] = name;
      if (!topic.empty()) j["topic"] = topic;
      j["reason"] = reason;
      j["score"] = score;
      j["num_joined_members"] = member_count;
      if (!shared_members.empty()) j["shared_members"] = shared_members;
      j["is_encrypted"] = is_encrypted;
      if (!room_type.empty()) j["room_type"] = room_type;
      if (last_active_ts > 0) j["last_active_ts"] = last_active_ts;
      return j;
    }
  };

  std::vector<RoomSuggestion> suggest_rooms(const std::string& user_id,
                                              const std::vector<std::string>& user_rooms,
                                              int limit = 10) {
    (void)user_id;
    std::vector<RoomSuggestion> suggestions;

    // Strategy 1: Suggest rooms with shared members
    std::unordered_set<std::string> user_room_set(user_rooms.begin(), user_rooms.end());
    std::map<std::string, int> shared_member_counts;

    // For each room the user is in, find other rooms with shared members
    for (const auto& rid : user_rooms) {
      if (!handler_) continue;
      auto entry = handler_->get_room_entry(rid);
      if (!entry) continue;
      // Find rooms with topic similarity
      for (const auto& rid2 : user_rooms) {
        if (rid == rid2) continue;
        auto entry2 = handler_->get_room_entry(rid2);
        if (!entry2) continue;
        shared_member_counts[rid2]++;
      }
    }

    // Strategy 2: Suggest popular rooms the user hasn't joined
    if (handler_) {
      auto published = handler_->list_public_rooms("", 100, "", "", "", false, false);
      if (published.contains("chunk") && published["chunk"].is_array()) {
        for (const auto& room : published["chunk"]) {
          std::string rid = safe_str(room, "room_id");
          if (user_room_set.count(rid)) continue;
          RoomSuggestion sugg;
          sugg.room_id = rid;
          sugg.name = safe_str(room, "name", rid);
          sugg.topic = safe_str(room, "topic", "");
          sugg.member_count = static_cast<int>(safe_int(room, "num_joined_members"));
          sugg.room_type = safe_str(room, "room_type", "");
          sugg.reason = "Popular room with " + std::to_string(sugg.member_count) + " members";
          sugg.score = sugg.member_count * 0.1;
          suggestions.push_back(sugg);
        }
      }
    }

    // Strategy 3: Deduplicate and sort by score
    std::sort(suggestions.begin(), suggestions.end(),
      [](const RoomSuggestion& a, const RoomSuggestion& b) {
        return a.score > b.score;
      });

    if (static_cast<int>(suggestions.size()) > limit) {
      suggestions.resize(limit);
    }

    return suggestions;
  }

  json suggest_rooms_json(const std::string& user_id,
                           const std::vector<std::string>& user_rooms,
                           int limit = 10) {
    auto suggestions = suggest_rooms(user_id, user_rooms, limit);
    json result;
    result["suggestions"] = json::array();
    for (const auto& s : suggestions) {
      result["suggestions"].push_back(s.to_json());
    }
    result["total"] = static_cast<int>(suggestions.size());
    return result;
  }

  // Suggest rooms based on interest/topic similarity
  std::vector<RoomSuggestion> suggest_by_interest(const std::string& interest_tag,
                                                    int limit = 10) {
    std::vector<RoomSuggestion> suggestions;

    if (!handler_) return suggestions;

    auto published = handler_->list_public_rooms("", 200, "", interest_tag, "", false, false);
    if (published.contains("chunk") && published["chunk"].is_array()) {
      int count = 0;
      for (const auto& room : published["chunk"]) {
        if (count >= limit) break;
        RoomSuggestion sugg;
        sugg.room_id = safe_str(room, "room_id");
        sugg.name = safe_str(room, "name", sugg.room_id);
        sugg.topic = safe_str(room, "topic", "");
        sugg.member_count = static_cast<int>(safe_int(room, "num_joined_members"));
        sugg.room_type = safe_str(room, "room_type", "");
        sugg.reason = "Matches interest: " + interest_tag;
        sugg.score = sugg.member_count * 0.1 + 5.0;
        suggestions.push_back(sugg);
        count++;
      }
    }

    std::sort(suggestions.begin(), suggestions.end(),
      [](const RoomSuggestion& a, const RoomSuggestion& b) {
        return a.score > b.score;
      });

    return suggestions;
  }

private:
  RoomDiscoveryHandler* handler_{nullptr};
};

// ============================================================================
// RoomTombstoneDiscovery - Track room upgrade chains
// ============================================================================

class RoomTombstoneDiscovery {
  struct TombstoneEntry {
    std::string old_room_id;
    std::string replacement_room_id;
    std::string reason;
    int64_t ts{0};
    std::string user_id;
  };

  std::unordered_map<std::string, TombstoneEntry> tombstones_;
  std::unordered_multimap<std::string, std::string> upgrade_chains_;
  std::mutex mutex_;

public:
  void register_tombstone(const std::string& old_room_id,
                           const std::string& new_room_id,
                           const std::string& reason = "",
                           const std::string& user_id = "") {
    std::lock_guard lock(mutex_);
    TombstoneEntry entry{old_room_id, new_room_id, reason, now_ms(), user_id};
    tombstones_[old_room_id] = entry;
    upgrade_chains_.emplace(old_room_id, new_room_id);
  }

  std::optional<std::string> get_successor_room(const std::string& room_id) {
    std::lock_guard lock(mutex_);
    auto it = tombstones_.find(room_id);
    if (it == tombstones_.end()) return std::nullopt;
    return it->second.replacement_room_id;
  }

  std::vector<std::string> get_upgrade_chain(const std::string& original_room_id) {
    std::lock_guard lock(mutex_);
    std::vector<std::string> chain;
    std::unordered_set<std::string> visited;
    std::string current = original_room_id;
    while (true) {
      if (visited.count(current)) break;
      visited.insert(current);
      chain.push_back(current);
      auto it = tombstones_.find(current);
      if (it == tombstones_.end()) break;
      current = it->second.replacement_room_id;
    }
    return chain;
  }

  json get_upgrade_chain_json(const std::string& room_id) {
    auto chain = get_upgrade_chain(room_id);
    json result = json::array();
    for (size_t i = 0; i < chain.size(); i++) {
      json entry;
      entry["room_id"] = chain[i];
      if (i < chain.size() - 1) {
        entry["predecessor"] = true;
      }
      if (i > 0) {
        entry["successor_of"] = chain[i - 1];
      }
      if (i == chain.size() - 1) {
        entry["current_version"] = true;
      }
      result.push_back(entry);
    }
    return result;
  }

  void remove_tombstone(const std::string& room_id) {
    std::lock_guard lock(mutex_);
    tombstones_.erase(room_id);
    auto range = upgrade_chains_.equal_range(room_id);
    upgrade_chains_.erase(range.first, range.second);
  }

  json get_all_tombstones() {
    std::lock_guard lock(mutex_);
    json result = json::object();
    for (const auto& [id, entry] : tombstones_) {
      json e;
      e["replacement_room"] = entry.replacement_room_id;
      if (!entry.reason.empty()) e["reason"] = entry.reason;
      if (!entry.user_id.empty()) e["sender"] = entry.user_id;
      e["timestamp"] = entry.ts;
      result[id] = e;
    }
    return result;
  }

  bool has_tombstone(const std::string& room_id) {
    std::lock_guard lock(mutex_);
    return tombstones_.count(room_id) > 0;
  }
};

// ============================================================================
// FederationAliasQuery - Handle federation alias queries
// ============================================================================

class FederationAliasQuery {
  struct CachedQuery {
    std::string alias;
    std::string room_id;
    std::vector<std::string> servers;
    int64_t cached_ts{0};
    int64_t ttl_ms{300000}; // 5 minutes
  };

  std::unordered_map<std::string, CachedQuery> query_cache_;
  std::mutex mutex_;
  RoomDiscoveryHandler* handler_{nullptr};

public:
  FederationAliasQuery() = default;
  explicit FederationAliasQuery(RoomDiscoveryHandler& h) : handler_(&h) {}

  json query_alias(const std::string& alias) {
    if (!validate_room_alias(alias)) {
      return json({{"errcode", "M_INVALID_PARAM"}, {"error", "Invalid alias"}});
    }

    // Check cache
    {
      std::lock_guard lock(mutex_);
      auto it = query_cache_.find(alias);
      if (it != query_cache_.end()) {
        int64_t age = now_ms() - it->second.cached_ts;
        if (age < it->second.ttl_ms) {
          json result;
          result["room_id"] = it->second.room_id;
          result["servers"] = it->second.servers;
          return result;
        }
      }
    }

    // Try local resolution
    if (handler_) {
      auto local_result = handler_->discover_room_by_alias(alias);
      if (!local_result.contains("errcode")) {
        // Cache successful result
        std::lock_guard lock(mutex_);
        CachedQuery cq;
        cq.alias = alias;
        cq.room_id = safe_str(local_result, "room_id");
        cq.servers = {"localhost"};
        cq.cached_ts = now_ms();
        query_cache_[alias] = cq;
        return local_result;
      }
    }

    return json({{"errcode", "M_NOT_FOUND"},
                 {"error", "Alias not found on this server"}});
  }

  json query_room_directory(const std::string& room_id) {
    if (!validate_room_id(room_id)) {
      return json({{"errcode", "M_INVALID_PARAM"}, {"error", "Invalid room ID"}});
    }

    if (!handler_) {
      return json({{"errcode", "M_NOT_FOUND"}, {"error", "Room not found"}});
    }

    auto entry = handler_->get_room_entry(room_id);
    if (!entry) {
      return json({{"errcode", "M_NOT_FOUND"}, {"error", "Room not found"}});
    }

    return entry->to_federation_chunk();
  }

  // Called when a remote server asks us about public rooms
  json handle_federation_public_rooms(const json& request) {
    if (!handler_) {
      return json({{"errcode", "M_UNKNOWN"}, {"error", "No handler available"}});
    }

    int limit = static_cast<int>(safe_int(request, "limit", 50));
    std::string since = safe_str(request, "since", "");
    std::string term = safe_str(request, "search_term", "");
    bool all_nets = safe_bool(request, "include_all_networks", false);
    bool tpi_only = safe_bool(request, "third_party_instance_only", false);
    std::string network = safe_str(request, "network", "");

    return handler_->federation_list_public_rooms(limit, since, term,
                                                    all_nets, tpi_only, network);
  }

  void invalidate_cache(const std::string& alias = "") {
    std::lock_guard lock(mutex_);
    if (alias.empty()) {
      query_cache_.clear();
    } else {
      query_cache_.erase(alias);
    }
  }

  void set_cache_ttl(int64_t ttl_ms) {
    std::lock_guard lock(mutex_);
    for (auto& [key, entry] : query_cache_) {
      entry.ttl_ms = ttl_ms;
    }
  }
};

// ============================================================================
// RoomDirectoryExport - Export/Import room directory data
// ============================================================================

class RoomDirectoryExport {
  RoomDiscoveryHandler* handler_{nullptr};

public:
  RoomDirectoryExport() = default;
  explicit RoomDirectoryExport(RoomDiscoveryHandler& h) : handler_(&h) {}

  json export_directory(const std::string& format = "json",
                         bool include_private = false) {
    if (!handler_) return json::object();

    json result;
    result["format"] = format;
    result["exported_at"] = now_ms();

    if (include_private) {
      // Export all rooms including private
      auto all_rooms = handler_->list_all_rooms(5000);
      result["rooms"] = all_rooms["chunk"];
      result["total_rooms"] = all_rooms["total_room_count"];
    } else {
      // Only public rooms
      auto public_rooms = handler_->list_public_rooms("", 5000);
      result["rooms"] = public_rooms["chunk"];
      result["total_rooms"] = public_rooms["total_room_count_estimate"];
    }

    // Include aliases
    json aliases = json::object();
    // Enumeration via the handler doesn't expose this directly, skip for now

    // Include statistics
    auto stats = handler_->get_room_statistics();
    result["statistics"] = stats;

    // Include protocols
    auto protocols = handler_->list_third_party_protocols();
    result["protocols"] = protocols;

    return result;
  }

  // Import rooms from an exported directory
  json import_directory(const json& data) {
    if (!handler_) {
      return json({{"errcode", "M_UNKNOWN"}, {"error", "No handler available"}});
    }

    int imported = 0;
    int skipped = 0;

    if (data.contains("rooms") && data["rooms"].is_array()) {
      for (const auto& room : data["rooms"]) {
        if (!room.contains("room_id")) {
          skipped++;
          continue;
        }

        std::string room_id = safe_str(room, "room_id");
        if (room_id.empty()) {
          skipped++;
          continue;
        }

        if (handler_->room_exists(room_id)) {
          // Update existing room
          handler_->update_room_name(room_id, safe_str(room, "name", ""));
          handler_->update_room_topic(room_id, safe_str(room, "topic", ""));
          handler_->update_room_avatar(room_id, safe_str(room, "avatar_url", ""));
          handler_->update_room_member_count(room_id,
                                              safe_int(room, "num_joined_members"));
          imported++;
        } else {
          handler_->register_room(room_id,
                                   safe_str(room, "name", ""),
                                   safe_str(room, "topic", ""),
                                   safe_str(room, "avatar_url", ""),
                                   safe_str(room, "room_type", ""),
                                   safe_str(room, "join_rule", "public"),
                                   safe_bool(room, "is_encrypted", false),
                                   safe_bool(room, "is_federatable", true),
                                   safe_str(room, "room_version", "1"),
                                   safe_str(room, "creator", ""));
          imported++;
        }

        // Set visibility
        if (room.contains("visibility")) {
          handler_->set_room_visibility(room_id, safe_str(room, "visibility", "private"));
        }
        if (safe_bool(room, "is_published", false)) {
          handler_->publish_room(room_id);
        }
      }
    }

    json result;
    result["imported"] = imported;
    result["skipped"] = skipped;
    return result;
  }
};

// ============================================================================
// RoomTypeFilter - Advanced room type filtering utilities
// ============================================================================

class RoomTypeFilter {
public:
  static std::vector<std::string> known_room_types() {
    return {
      "m.space",
      "m.direct",
      "m.room",
      "m.policy",
      "m.bridge",
      "m.group",
      "m.community",
      "m.meeting",
      "m.announcement",
      "m.forum",
      "m.support",
      "m.welcome",
      "m.bot",
      "m.integration"
    };
  }

  static std::vector<std::string> filter_rooms_by_type(
      const std::vector<RoomDirectoryEntry>& rooms,
      const std::string& room_type) {
    std::vector<std::string> result;
    for (const auto& entry : rooms) {
      if (entry.room_type == room_type) {
        result.push_back(entry.room_id);
      }
    }
    return result;
  }

  static json categorize_rooms(const std::vector<RoomDirectoryEntry>& rooms) {
    json categories = json::object();
    for (const auto& entry : rooms) {
      std::string cat = entry.room_type.empty() ? "room" : entry.room_type;
      if (!categories.contains(cat)) {
        categories[cat] = json::array();
      }
      categories[cat].push_back(entry.room_id);
    }
    return categories;
  }

  static json categorize_rooms_by_visibility(
      const std::vector<RoomDirectoryEntry>& rooms) {
    json cats = json::object();
    cats["public"] = json::array();
    cats["private"] = json::array();
    cats["world_readable"] = json::array();
    for (const auto& entry : rooms) {
      if (entry.is_published || entry.visibility == "public") {
        cats["public"].push_back(entry.room_id);
      } else {
        cats["private"].push_back(entry.room_id);
      }
      if (entry.world_readable == "world_readable") {
        cats["world_readable"].push_back(entry.room_id);
      }
    }
    return cats;
  }
};

// ============================================================================
// DiscoveryHealthCheck - Monitor directory health
// ============================================================================

class DiscoveryHealthCheck {
  int64_t last_check_ts_{0};
  int check_interval_ms_{300000}; // 5 minutes
  std::mutex mutex_;

public:
  struct HealthStatus {
    bool ok{true};
    int total_rooms{0};
    int published_rooms{0};
    int orphaned_aliases{0};
    int stale_entries{0};
    int64_t oldest_entry_ts{0};
    int64_t newest_entry_ts{0};
    std::vector<std::string> issues;
    int64_t check_ts{0};
  };

  HealthStatus check(RoomDiscoveryHandler& handler) {
    std::lock_guard lock(mutex_);
    HealthStatus status;
    status.check_ts = now_ms();

    auto all_rooms = handler.list_all_rooms(10000);
    status.total_rooms = static_cast<int>(safe_int(all_rooms, "total_room_count"));
    status.published_rooms = static_cast<int>(handler.get_published_room_count());

    // Check for stale entries (rooms with no activity in 90 days)
    int64_t cutoff = now_ms() - (86400000LL * 90);
    if (all_rooms.contains("chunk") && all_rooms["chunk"].is_array()) {
      for (const auto& room : all_rooms["chunk"]) {
        int64_t last_active = safe_int(room, "last_active_ts", 0);
        if (last_active > 0 && last_active < cutoff) {
          status.stale_entries++;
        }
        int64_t created = safe_int(room, "created_ts", 0);
        if (created > 0 && (status.oldest_entry_ts == 0 || created < status.oldest_entry_ts)) {
          status.oldest_entry_ts = created;
        }
        if (last_active > status.newest_entry_ts) {
          status.newest_entry_ts = last_active;
        }
      }
    }

    if (status.stale_entries > status.total_rooms / 2) {
      status.issues.push_back("More than 50% of rooms are stale (no activity in 90 days)");
      status.ok = false;
    }

    if (status.total_rooms == 0) {
      status.issues.push_back("No rooms in directory");
      status.ok = false;
    }

    if (status.published_rooms == 0) {
      status.issues.push_back("No published rooms");
    }

    last_check_ts_ = status.check_ts;
    return status;
  }

  json check_json(RoomDiscoveryHandler& handler) {
    auto status = check(handler);
    json j;
    j["ok"] = status.ok;
    j["total_rooms"] = status.total_rooms;
    j["published_rooms"] = status.published_rooms;
    j["orphaned_aliases"] = status.orphaned_aliases;
    j["stale_entries"] = status.stale_entries;
    j["oldest_entry_ts"] = status.oldest_entry_ts;
    j["newest_entry_ts"] = status.newest_entry_ts;
    j["issues"] = status.issues;
    j["check_ts"] = status.check_ts;
    return j;
  }

  void set_check_interval(int ms) {
    std::lock_guard lock(mutex_);
    check_interval_ms_ = ms;
  }
};

} // namespace progressive::handlers
