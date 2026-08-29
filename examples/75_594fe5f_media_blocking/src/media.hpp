// media.hpp — translation of Conduit's src/database/media.rs (as of 594fe5f)
//
//   pub struct Media {
//     mediaid_file: sled::Tree,               // sha256(content) -> bytes
//     mediaid_meta: sled::Tree,               // server + 0xff + media_id -> metadata json
//     blocked_servername_mediaid: sled::Tree, // server + 0xff + media_id -> block time + reason
//     blocked_filehash: sled::Tree,           // sha256_hex -> block time + reason
//   }
//
// 70d7f77: media bytes are stored keyed by the sha256 of their content
// (deduplication), while metadata (filename, content_type, created_at,
// file_size, sha256 digest) lives in a separate tree keyed by
// server_name + 0xff + media_id.
// 594fe5f: admins can block media by (server, media_id) or by uploader; blocked
// media (directly, or because its content sha256 is blocked) is 404'd.

#pragma once

#include "sled.hpp"

#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <vector>

namespace database {

class Media {
 public:
  explicit Media(sled::Tree tree, sled::Tree meta, sled::Tree blocked,
                 sled::Tree blocked_hash)
      : tree_(std::move(tree)),
        meta_(std::move(meta)),
        blocked_(std::move(blocked)),
        blocked_hash_(std::move(blocked_hash)) {}

  /// Uploads or replaces a file. The on-disk key is the sha256 of `file`
  /// (so identical content is deduplicated); `meta` records the mapping from
  /// (server_name, media_id) to that digest. If the content sha256 is blocked,
  /// only the metadata is recorded — the bytes are not stored (mirrors
  /// Conduit's is_blocked_filehash check in create_file_metadata).
  void create(const std::string& server_name, const std::string& media_id,
              const std::optional<std::string>& filename,
              const std::optional<std::string>& content_type, const std::string& file,
              bool unauthenticated_access_permitted,
              const std::optional<std::string>& user_id);

  /// Downloads a file: (filename, content_type, bytes).
  struct File {
    std::optional<std::string> filename;
    std::string content_type;
    std::string bytes;
  };
  std::optional<File> get(const std::string& server_name,
                          const std::string& media_id,
                          bool authenticated) const;

  // NEW in d766370: media purge support.
  // Remove a single media entry. Returns true if it existed. The underlying
  // bytes are also deleted when `force` is set or no other meta references the
  // same sha256 (deduplicated content).
  bool remove(const std::string& server_name, const std::string& media_id, bool force);
  // Remove every media uploaded by `user_id` (the full "@local:server" id) on
  // `server_name`, optionally only entries created at/after `after_ms`. Returns
  // the number of media removed.
  size_t remove_by_user(const std::string& server_name, const std::string& user_id,
                        bool force, const std::optional<uint64_t>& after_ms);
  // Remove every media on `server_name` created at/after `after_ms` (if set).
  size_t remove_by_server(const std::string& server_name, bool force,
                          const std::optional<uint64_t>& after_ms);

  // NEW in 594fe5f: media blocking support.
  // Checks whether (server_name, media_id) is blocked, either directly or via
  // the sha256 of its content (a blocked filehash blocks all references).
  bool is_blocked(const std::string& server_name, const std::string& media_id) const;
  bool is_blocked_filehash(const std::string& digest) const;
  // Block and return the media's content hash if it exists.
  void block(const std::string& server_name, const std::string& media_id,
             const std::string& reason, uint64_t unix_secs);
  // Block every media on `server_name` uploaded by `user_id`, optionally only
  // entries created at/after `after_secs`. Returns the number blocked.
  size_t block_by_user(const std::string& server_name, const std::string& user_id,
                       const std::string& reason, uint64_t unix_secs,
                       const std::optional<uint64_t>& after_secs);
  // Unblock (server_name, media_id). Returns true if it was blocked.
  bool unblock(const std::string& server_name, const std::string& media_id);

  struct BlockedMediaInfo {
    std::string server_name;
    std::string media_id;
    uint64_t unix_secs;
    std::optional<std::string> reason;
    std::optional<std::string> sha256_hex;
  };
  std::vector<BlockedMediaInfo> list_blocked() const;

 private:
  sled::Tree tree_;           // sha256_digest -> file bytes
  sled::Tree meta_;           // server_name + 0xff + media_id -> metadata json
  sled::Tree blocked_;        // server_name + 0xff + media_id -> 8-byte secs + reason
  sled::Tree blocked_hash_;   // sha256_hex -> 8-byte secs + reason

  size_t count_references(const std::string& digest) const;
  static std::string blocked_value(uint64_t unix_secs, const std::string& reason);
};

}  // namespace database
