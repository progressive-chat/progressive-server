#pragma once
// directory.hpp - directory.py C++ translation
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "progressive/storage/database.hpp"
namespace progressive::storage { using json = nlohmann::json;

struct RoomAlias {
  std::string room_alias;
  std::string room_id;
  std::string creator;
  std::vector<std::string> servers;
};

class DirectoryStore {
public:
  explicit DirectoryStore(DatabasePool& db);
  // Create alias
  void create_alias(const std::string& room_alias, const std::string& room_id,
      const std::string& creator, const std::vector<std::string>& servers = {});
  // Delete alias
  void delete_alias(const std::string& room_alias);
  // Get room ID for alias
  std::optional<std::string> get_room_id(const std::string& room_alias);
  // Get aliases for room
  std::vector<std::string> get_aliases_for_room(const std::string& room_id);
  // Get servers for alias
  std::vector<std::string> get_servers_for_alias(const std::string& room_alias);
  // Add/remove servers
  void add_alias_servers(const std::string& room_alias, const std::vector<std::string>& servers);
  void remove_alias_servers(const std::string& room_alias, const std::vector<std::string>& servers);
  // Get alias creator
  std::optional<std::string> get_alias_creator(const std::string& room_alias);
  // List published rooms (from room directory)
  struct PublicRoom {
    std::string room_id; std::string name; std::string topic;
    int64_t num_joined_members{0}; std::string room_type;
    bool world_readable{false}; std::optional<std::string> avatar_url;
    std::optional<std::string> canonical_alias;
  };
  std::vector<PublicRoom> get_public_rooms(const std::string& server = "",
      int64_t limit = 100, int64_t since = 0, const std::string& search_term = "",
      const std::string& network = "", bool include_all = false);
  // Set room visibility in directory
  void set_room_visibility(const std::string& room_id, const std::string& visibility);
  // Get room visibility
  std::optional<std::string> get_room_visibility(const std::string& room_id);
  // Check if alias is local
  bool is_local_alias(const std::string& room_alias);
  // Get all local aliases
  std::vector<RoomAlias> get_all_local_aliases(int64_t limit = 100, int64_t offset = 0);
private:
  DatabasePool& db_;
};
} // namespace
