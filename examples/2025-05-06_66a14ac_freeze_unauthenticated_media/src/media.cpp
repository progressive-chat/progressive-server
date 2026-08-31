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
                   const std::optional<std::string>& content_type,
                   const std::string& file,
                   bool unauthenticated_access_permitted) {
  const std::string digest = sha256_hex(file);
  // Deduplicate: identical bytes are stored once, keyed by their content hash.
  tree_.insert(digest, file);

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

}  // namespace database
