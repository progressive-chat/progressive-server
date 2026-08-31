// media.hpp — translation of Conduit commit 821c608c's src/database/media.rs
//
//   pub struct Media { mediaid_file: sled::Tree }  // MXC + Filename + ContentType
//
//   create(mxc, filename, content_type, file): store under one key
//   get(mxc): first entry with prefix mxc+0xff -> (filename, content_type, file)

#pragma once

#include "sled.hpp"

#include <optional>
#include <string>

namespace database {

class Media {
 public:
  explicit Media(sled::Tree tree) : tree_(std::move(tree)) {}

  /// Uploads or replaces a file.
  void create(const std::string& mxc, const std::optional<std::string>& filename,
              const std::string& content_type, const std::string& file);

  /// Downloads a file: (filename, content_type, bytes).
  struct File {
    std::optional<std::string> filename;
    std::string content_type;
    std::string bytes;
  };
  std::optional<File> get(const std::string& mxc) const;

 private:
  sled::Tree tree_;
};

}  // namespace database
