// media.cpp — translation of Conduit's src/database/media.rs (as of 70d7f77)
//
// Storage model:
//   mediaid_file: sha256_hex(content) -> content bytes (deduplicated)
//   mediaid_meta: server_name + 0xff + media_id -> json {
//       "sha256": <sha256_hex>, "filename": <str|null>,
//       "content_type": <str>, "created_at": <ms>, "file_size": <bytes> }

#include "media.hpp"

#include <openssl/sha.h>

#include "utils.hpp"

namespace database {

namespace {

std::string sha256_hex(const std::string& data) {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);
  static const char* hex = "0123456789abcdef";
  std::string out;
  out.reserve(SHA256_DIGEST_LENGTH * 2);
  for (unsigned char c : hash) {
    out.push_back(hex[c >> 4]);
    out.push_back(hex[c & 0xf]);
  }
  return out;
}

std::string meta_key(const std::string& server_name, const std::string& media_id) {
  return server_name + static_cast<char>(0xff) + media_id;
}

}  // namespace

void Media::create(const std::string& server_name, const std::string& media_id,
                   const std::optional<std::string>& filename,
                   const std::optional<std::string>& content_type, const std::string& file,
                   bool unauthenticated_access_permitted,
                   const std::optional<std::string>& user_id) {
  const std::string digest = sha256_hex(file);
  // NEW in 594fe5f: blocked content is never stored. Only the metadata is kept
  // (so the media is visible as blocked/not-found), mirroring Conduit's
  // is_blocked_filehash check in create_file_metadata.
  if (!is_blocked_filehash(digest)) {
    // Deduplicate: identical bytes are stored once, keyed by their content hash.
    tree_.insert(digest, file);
  }

  nlohmann::json meta = nlohmann::json::object();
  meta["sha256"] = digest;
  if (filename) {
    meta["filename"] = *filename;
  } else {
    meta["filename"] = nullptr;
  }
  meta["content_type"] = content_type.value_or("application/octet-stream");
  meta["created_at"] = utils::millis_since_unix_epoch();
  meta["file_size"] = static_cast<long long>(file.size());
  // NEW in 66a14ac: snapshot whether unauthenticated access is permitted at the
  // time of upload. Once frozen (false), only authenticated endpoints can fetch
  // this media afterwards — independent of later config changes.
  meta["unauthenticated_access_permitted"] = unauthenticated_access_permitted;
  // NEW in 3171b77: record the uploader so media can later be enumerated/purged
  // per user. Remote (federated) media has no local uploader.
  if (user_id) {
    meta["user_id"] = *user_id;
  } else {
    meta["user_id"] = nullptr;
  }
  meta_.insert(meta_key(server_name, media_id), meta.dump());
}

std::optional<Media::File> Media::get(const std::string& server_name,
                                      const std::string& media_id,
                                      bool authenticated) const {
  auto raw = meta_.get(meta_key(server_name, media_id));
  if (!raw) return std::nullopt;

  const nlohmann::json meta = nlohmann::json::parse(*raw, nullptr, false);
  if (meta.is_discarded() || !meta.contains("sha256")) return std::nullopt;

  // NEW in 66a14ac: freeze unauthenticated media. Unauthenticated callers may
  // only fetch media whose upload snapshot permitted it.
  const bool unauthenticated_access_permitted =
      meta.value("unauthenticated_access_permitted", false);
  if (!(authenticated || unauthenticated_access_permitted)) {
    return std::nullopt;
  }

  auto bytes = tree_.get(meta["sha256"].get<std::string>());
  if (!bytes) return std::nullopt;

  File out;
  out.bytes = *bytes;
  if (meta.contains("filename") && !meta["filename"].is_null()) {
    out.filename = meta["filename"].get<std::string>();
  }
  out.content_type = meta.value("content_type", std::string("application/octet-stream"));
  return out;
}

size_t Media::count_references(const std::string& digest) const {
  if (digest.empty()) return 0;
  size_t count = 0;
  for (const auto& [key, value] : meta_.scan_prefix("")) {
    const nlohmann::json m = nlohmann::json::parse(value, nullptr, false);
    if (m.is_discarded()) continue;
    if (m.value("sha256", std::string()) == digest) ++count;
  }
  return count;
}

bool Media::remove(const std::string& server_name, const std::string& media_id, bool force) {
  const std::string key = meta_key(server_name, media_id);
  auto raw = meta_.get(key);
  if (!raw) return false;
  const nlohmann::json meta = nlohmann::json::parse(*raw, nullptr, false);
  const std::string digest = meta.contains("sha256") ? meta["sha256"].get<std::string>() : "";
  meta_.erase(key);
  // Drop the bytes only when nothing else references them (or when forced).
  if (!digest.empty() && (force || count_references(digest) == 0)) {
    tree_.erase(digest);
  }
  return true;
}

size_t Media::remove_by_user(const std::string& server_name, const std::string& user_id,
                             bool force, const std::optional<uint64_t>& after_ms) {
  std::vector<std::pair<std::string, std::string>> targets;
  for (const auto& [key, value] : meta_.scan_prefix("")) {
    const nlohmann::json m = nlohmann::json::parse(value, nullptr, false);
    if (m.is_discarded()) continue;
    if (m.value("user_id", std::string()) != user_id) continue;
    size_t ff = key.find(static_cast<char>(0xff));
    if (ff == std::string::npos) continue;
    const std::string server = key.substr(0, ff);
    if (server != server_name) continue;
    if (after_ms && m.value("created_at", static_cast<uint64_t>(0)) < *after_ms) continue;
    targets.emplace_back(server, key.substr(ff + 1));
  }
  size_t removed = 0;
  for (const auto& [s, id] : targets)
    if (remove(s, id, force)) ++removed;
  return removed;
}

size_t Media::remove_by_server(const std::string& server_name, bool force,
                               const std::optional<uint64_t>& after_ms) {
  std::vector<std::pair<std::string, std::string>> targets;
  for (const auto& [key, value] : meta_.scan_prefix(server_name + static_cast<char>(0xff))) {
    const nlohmann::json m = nlohmann::json::parse(value, nullptr, false);
    if (m.is_discarded()) continue;
    if (after_ms && m.value("created_at", static_cast<uint64_t>(0)) < *after_ms) continue;
    size_t ff = key.find(static_cast<char>(0xff));
    targets.emplace_back(server_name, key.substr(ff + 1));
  }
  size_t removed = 0;
  for (const auto& [s, id] : targets)
    if (remove(s, id, force)) ++removed;
  return removed;
}

// ---- NEW in 594fe5f: media blocking ----------------------------------------

// Value format for the blocked trees: 8 bytes big-endian unix_secs + reason.
std::string Media::blocked_value(uint64_t unix_secs, const std::string& reason) {
  std::string out;
  for (int i = 7; i >= 0; --i) out.push_back(static_cast<char>((unix_secs >> (8 * i)) & 0xff));
  out += reason;
  return out;
}

bool Media::is_blocked_filehash(const std::string& digest) const {
  return blocked_hash_.get(digest).has_value();
}

bool Media::is_blocked(const std::string& server_name, const std::string& media_id) const {
  // Directly blocked?
  if (blocked_.get(meta_key(server_name, media_id)).has_value()) return true;
  // Blocked via the content hash of the stored metadata.
  auto raw = meta_.get(meta_key(server_name, media_id));
  if (raw) {
    const nlohmann::json m = nlohmann::json::parse(*raw, nullptr, false);
    if (!m.is_discarded() && m.value("sha256", std::string()).empty() == false) {
      if (is_blocked_filehash(m["sha256"].get<std::string>())) return true;
    }
  }
  return false;
}

void Media::block(const std::string& server_name, const std::string& media_id,
                  const std::string& reason, uint64_t unix_secs) {
  const auto raw = meta_.get(meta_key(server_name, media_id));
  std::optional<std::string> digest;
  if (raw) {
    const nlohmann::json m = nlohmann::json::parse(*raw, nullptr, false);
    if (!m.is_discarded()) digest = m.value("sha256", std::string());
  }
  blocked_.insert(meta_key(server_name, media_id), blocked_value(unix_secs, reason));
  // Also block the underlying content hash so identical content uploaded under
  // another media_id is blocked too. Do not overwrite an earlier block time.
  if (digest && !digest->empty() && !blocked_hash_.get(*digest).has_value()) {
    blocked_hash_.insert(*digest, blocked_value(unix_secs, reason));
  }
}

size_t Media::block_by_user(const std::string& server_name, const std::string& user_id,
                            const std::string& reason, uint64_t unix_secs,
                            const std::optional<uint64_t>& after_secs) {
  std::vector<std::pair<std::string, std::string>> targets;
  for (const auto& [key, value] : meta_.scan_prefix("")) {
    const nlohmann::json m = nlohmann::json::parse(value, nullptr, false);
    if (m.is_discarded()) continue;
    if (m.value("user_id", std::string()) != user_id) continue;
    size_t ff = key.find(static_cast<char>(0xff));
    if (ff == std::string::npos) continue;
    if (key.substr(0, ff) != server_name) continue;
    // Conduit only blocks media created after `after` (a unix-seconds threshold).
    if (after_secs &&
        m.value("created_at", static_cast<uint64_t>(0)) / 1000 < *after_secs) {
      continue;
    }
    targets.emplace_back(server_name, key.substr(ff + 1));
  }
  for (const auto& [s, id] : targets) block(s, id, reason, unix_secs);
  return targets.size();
}

bool Media::unblock(const std::string& server_name, const std::string& media_id) {
  if (!blocked_.get(meta_key(server_name, media_id)).has_value()) return false;
  blocked_.erase(meta_key(server_name, media_id));
  // Drop the content-hash block if no remaining blocked media references it.
  auto raw = meta_.get(meta_key(server_name, media_id));
  if (raw) {
    const nlohmann::json m = nlohmann::json::parse(*raw, nullptr, false);
    if (!m.is_discarded()) {
      const std::string digest = m.value("sha256", std::string());
      if (!digest.empty() && blocked_hash_.get(digest).has_value()) {
        // only remove if no other blocked entry shares this content hash
        bool still_blocked = false;
        for (const auto& [k2, v2] : blocked_.scan_prefix("")) {
          if (k2 == meta_key(server_name, media_id)) continue;
          auto r = meta_.get(k2);
          if (r) {
            const nlohmann::json m2 = nlohmann::json::parse(*r, nullptr, false);
            if (!m2.is_discarded() && m2.value("sha256", std::string()) == digest) {
              still_blocked = true;
              break;
            }
          }
        }
        if (!still_blocked) blocked_hash_.erase(digest);
      }
    }
  }
  return true;
}

std::vector<Media::BlockedMediaInfo> Media::list_blocked() const {
  std::vector<BlockedMediaInfo> out;
  for (const auto& [key, value] : blocked_.scan_prefix("")) {
    size_t ff = key.find(static_cast<char>(0xff));
    if (ff == std::string::npos) continue;
    BlockedMediaInfo info;
    info.server_name = key.substr(0, ff);
    info.media_id = key.substr(ff + 1);
    uint64_t secs = 0;
    size_t i = 0;
    for (; i < 8 && i < value.size(); ++i) secs = (secs << 8) | (static_cast<unsigned char>(value[i]) & 0xff);
    info.unix_secs = secs;
    if (value.size() > 8) info.reason = value.substr(8);
    auto raw = meta_.get(key);
    if (raw) {
      const nlohmann::json m = nlohmann::json::parse(*raw, nullptr, false);
      if (!m.is_discarded()) info.sha256_hex = m.value("sha256", std::string());
    }
    out.push_back(std::move(info));
  }
  return out;
}

}  // namespace database
