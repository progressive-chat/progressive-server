// media.hpp — translation of Conduit commit 821c608c's src/database/media.rs
//
//   pub struct Media { mediaid_file: sled::Tree }  // MXC + Filename + ContentType
//
//   create(mxc, filename, content_type, file): store under one key
//   get(mxc): first entry with prefix mxc+0xff -> (filename, content_type, file)
//   upload_thumbnail(mxc, filename, content_type, width, height, file): store thumbnail with dimensions
//
// NEW in 972caacd: blobs live in <data_dir>/media/<base64url(key)> files; the
// tree keeps metadata-only entries (empty values). Entries written before this
// step still serve from their inline bytes (transparent fallback).

#pragma once

#include "sled.hpp"

#include <filesystem>
#include <optional>
#include <string>

namespace database {

class Media {
 public:
  explicit Media(sled::Tree tree) : tree_(std::move(tree)) {}

  /// Directory holding media blobs (<data_dir>/media). Must be set via
  /// set_dir() before use (Data does this at startup).
  void set_dir(std::filesystem::path dir);

  /// Uploads or replaces a file.
  void create(const std::string& mxc, const std::optional<std::string>& filename,
              const std::string& content_type, const std::string& file);

  /// Uploads or replaces a thumbnail.
  void upload_thumbnail(const std::string& mxc,
                        const std::optional<std::string>& filename,
                        const std::string& content_type,
                        uint32_t width, uint32_t height,
                        const std::string& file);

  /// NEW in 6bb8284: Returns width, height of the thumbnail and whether it
  /// should be cropped. Returns None when the server should send the original
  /// file. Standard thumbnail sizes: 32x32, 96x96, 320x240, 640x480, 800x600.
  std::optional<std::tuple<uint32_t, uint32_t, bool>> thumbnail_properties(
      uint32_t width, uint32_t height) const;

  /// Downloads a file: (filename, content_type, bytes).
  struct File {
    std::optional<std::string> filename;
    std::string content_type;
    std::string bytes;
  };
  std::optional<File> get(const std::string& mxc) const;

 private:
  /// Blob path for a tree key (upstream get_media_file: media/<base64url>).
  std::filesystem::path file_path(const std::string& key) const;
  void store_bytes(const std::string& key, const std::string& file);
  std::optional<std::string> load_bytes(const std::string& key,
                                        const std::string& stored) const;

  sled::Tree tree_;
  std::filesystem::path dir_;
};

}  // namespace database
