#pragma once
// profile.hpp - C++ translation of profile.py
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

struct UserProfile {
  std::string user_id;
  std::optional<std::string> display_name;
  std::optional<std::string> avatar_url;
};

class ProfileStore {
public:
  explicit ProfileStore(DatabasePool& db);
  // Get user profile
  std::optional<UserProfile> get_profile(const std::string& user_id);
  // Set display name
  void set_display_name(const std::string& user_id, const std::string& display_name);
  // Set avatar URL
  void set_avatar_url(const std::string& user_id, const std::string& avatar_url);
  // Set full profile
  void set_profile(const std::string& user_id, const std::string& display_name,
      const std::string& avatar_url);
  // Get profiles for multiple users
  std::map<std::string, UserProfile> get_profiles(const std::set<std::string>& user_ids);
  // Search user directory by display name
  struct UserDirEntry { std::string user_id; std::string display_name; std::optional<std::string> avatar_url; };
  std::vector<UserDirEntry> search_user_directory(const std::string& search_term, int limit = 10);
  // Add to user directory
  void add_to_user_directory(const std::string& user_id, const std::string& display_name,
      const std::optional<std::string>& avatar_url);
  // Remove from user directory
  void remove_from_user_directory(const std::string& user_id);
  // Update user directory profile
  void update_user_directory_profile(const std::string& user_id,
      const std::string& display_name, const std::optional<std::string>& avatar_url);
  // Check if user should be in directory
  bool is_user_in_directory(const std::string& user_id);
  // Get all users in directory
  std::vector<UserDirEntry> get_all_users_in_directory(int64_t offset = 0, int64_t limit = 100);
private:
  DatabasePool& db_;
};
} // namespace
