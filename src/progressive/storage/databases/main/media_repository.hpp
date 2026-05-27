#pragma once
// media_repository.hpp - media_repository.py C++ translation
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "progressive/storage/database.hpp"
namespace progressive::storage { using json = nlohmann::json;

struct MediaInfo {
  std::string media_id; std::string media_type; std::string upload_name;
  std::string user_id; int64_t created_ts{0}; int64_t last_access_ts{0};
  int64_t media_length{0}; std::string content_type;
  std::optional<int64_t> thumbnail_width; std::optional<int64_t> thumbnail_height;
  std::optional<std::string> thumbnail_type; std::optional<std::string> thumbnail_method;
  bool quarantined{false}; bool safe_from_quarantine{false};
};

class MediaRepositoryStore {
public:
  explicit MediaRepositoryStore(DatabasePool& db);
  // Store local media
  void store_local_media(const std::string& media_id, const std::string& media_type,
      const std::string& upload_name, const std::string& user_id, int64_t media_length,
      const std::string& content_type, int64_t created_ts);
  // Get local media
  std::optional<MediaInfo> get_local_media(const std::string& media_id);
  // Get local media by user
  std::vector<MediaInfo> get_local_media_by_user(const std::string& user_id, int64_t limit, int64_t offset);
  // Delete local media
  void delete_local_media(const std::string& media_id);
  // Update last access time
  void update_cached_last_access_time(const std::string& media_id, int64_t ts);
  // Store remote media cache
  void store_cached_remote_media(const std::string& origin, const std::string& media_id,
      const std::string& media_type, int64_t media_length, const std::string& content_type,
      int64_t created_ts, const std::string& upload_name, const std::string& filesystem_id);
  // Get remote media
  std::optional<MediaInfo> get_cached_remote_media(const std::string& origin, const std::string& media_id);
  // Store thumbnail
  void store_local_thumbnail(const std::string& media_id, int64_t width, int64_t height,
      const std::string& thumbnail_type, const std::string& thumbnail_method, int64_t length);
  // Get thumbnails for media
  std::vector<MediaInfo> get_local_thumbnails(const std::string& media_id);
  // Mark media as quarantined
  void quarantine_media(const std::string& media_id, bool quarantined);
  void quarantine_media_by_user(const std::string& user_id, bool quarantined);
  void quarantine_media_by_room(const std::string& room_id, bool quarantined);
  // Get quarantine status
  bool is_media_quarantined(const std::string& media_id);
  // Get URL preview cache
  void store_url_preview(const std::string& url, int64_t ts, const json& preview_data, int64_t og_ts);
  std::optional<json> get_url_preview(const std::string& url, int64_t min_ts);
  // Expire old remote media
  void expire_old_remote_media(int64_t before_ts);
  // Count media by user
  int64_t count_local_media_by_user(const std::string& user_id);
  // Get total local media size
  int64_t get_total_local_media_size();
  // Get total cached remote media size
  int64_t get_total_cached_remote_media_size();
private:
  DatabasePool& db_;
};
} // namespace
