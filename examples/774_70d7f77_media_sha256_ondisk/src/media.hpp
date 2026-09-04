// media.hpp — translation of Conduit's src/database/media.rs (as of 70d7f77)
//
//   pub struct Media { mediaid_file: sled::Tree, mediaid_meta: sled::Tree }
//
// 70d7f77: media bytes are stored keyed by the sha256 of their content
// (deduplication), while metadata (filename, content_type, created_at,
// file_size, sha256 digest) lives in a separate tree keyed by
// server_name + 0xff + media_id.

#pragma once

#include "sled.hpp"

#include <nlohmann/json.hpp>
#include <optional>
#include <string>

namespace database {

class Media {
 public:
  explicit Media(sled::Tree tree, sled::Tree meta)
      : tree_(std::move(tree)), meta_(std::move(meta)) {}

  /// Uploads or replaces a file. The on-disk key is the sha256 of `file`
  /// (so identical content is deduplicated); `meta` records the mapping from
  /// (server_name, media_id) to that digest.
  void create(const std::string& server_name, const std::string& media_id,
              const std::optional<std::string>& filename,
              const std::optional<std::string>& content_type,
              const std::string& file);

  /// Downloads a file: (filename, content_type, bytes).
  struct File {
    std::optional<std::string> filename;
    std::string content_type;
    std::string bytes;
  };
  std::optional<File> get(const std::string& server_name,
                          const std::string& media_id) const;

 private:
  sled::Tree tree_;  // sha256_digest -> file bytes
  sled::Tree meta_;  // server_name + 0xff + media_id -> metadata json
};

}  // namespace database
