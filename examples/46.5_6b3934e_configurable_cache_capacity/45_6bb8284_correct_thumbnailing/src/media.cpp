#include "media.hpp"

namespace database {

namespace {
// MediaId = MXC + 0xff + Filename + 0xff + ContentType
std::string media_key(const std::string& mxc, const std::optional<std::string>& filename,
                      const std::string& content_type) {
  std::string key = mxc;
  key.push_back(static_cast<char>(0xff));
  if (filename) key += *filename;
  key.push_back(static_cast<char>(0xff));
  key += content_type;
  return key;
}
}  // namespace

void Media::create(const std::string& mxc, const std::optional<std::string>& filename,
                   const std::string& content_type, const std::string& file) {
  tree_.insert(media_key(mxc, filename, content_type), file);
}

std::optional<Media::File> Media::get(const std::string& mxc) const {
  std::string prefix = mxc;
  prefix.push_back(static_cast<char>(0xff));

  const auto entries = tree_.scan_prefix(prefix);
  if (entries.empty()) return std::nullopt;

  // First entry wins; the key is MXC + 0xff + filename + 0xff + content_type.
  const std::string& key = entries[0].first;
  const std::string& file = entries[0].second;

  std::vector<std::string> parts;
  size_t start = key.size() - mxc.size() - 1;  // skip "mxc" + 0xff
  while (true) {
    const size_t ff = key.find(static_cast<char>(0xff), start);
    if (ff == std::string::npos) {
      parts.push_back(key.substr(start));
      break;
    }
    parts.push_back(key.substr(start, ff - start));
    start = ff + 1;
  }

  File out;
  out.bytes = file;
  if (parts.size() >= 2 && !parts[1].empty()) out.filename = parts[1];
  if (parts.size() >= 3) out.content_type = parts[2];
  return out;
}

/// Uploads or replaces a thumbnail with width/height metadata.
/// Key format: MXC + 0xff + width (be) + 0xff + height (be) + 0xff + filename + 0xff + content_type
void Media::upload_thumbnail(const std::string& mxc,
                             const std::optional<std::string>& filename,
                             const std::string& content_type,
                             uint32_t width, uint32_t height,
                             const std::string& file) {
  std::string key = mxc;
  key.push_back(static_cast<char>(0xff));
  key.append(reinterpret_cast<const char*>(&width), sizeof(width));
  key.push_back(static_cast<char>(0xff));
  key.append(reinterpret_cast<const char*>(&height), sizeof(height));
  key.push_back(static_cast<char>(0xff));
  if (filename) key += *filename;
  key.push_back(static_cast<char>(0xff));
  key += content_type;
  tree_.insert(key, file);
}

/// NEW in 6bb8284: Returns width, height of the thumbnail and whether it
/// should be cropped. Returns None when the server should send the original
/// file. Standard thumbnail sizes: 32x32, 96x96, 320x240, 640x480, 800x600.
std::optional<std::tuple<uint32_t, uint32_t, bool>> Media::thumbnail_properties(
    uint32_t width, uint32_t height) const {
  if (width <= 32 && height <= 32) return std::make_tuple(32u, 32u, true);
  if (width <= 96 && height <= 96) return std::make_tuple(96u, 96u, true);
  if (width <= 320 && height <= 240) return std::make_tuple(320u, 240u, false);
  if (width <= 640 && height <= 480) return std::make_tuple(640u, 480u, false);
  if (width <= 800 && height <= 600) return std::make_tuple(800u, 600u, false);
  return std::nullopt;
}

}  // namespace database
