#pragma once
#include <string>
#include <string_view>

namespace progressive::urlpreview {

struct PreviewResult {
  std::string title;
  std::string description;
  std::string image_url;
  std::string og_type;
  int64_t image_size = 0;
};

inline PreviewResult extract_og_tags(std::string_view html) {
  PreviewResult r;
  // Extract <meta property="og:title" content="..." />
  auto tpos = html.find("og:title");
  if (tpos != std::string_view::npos) {
    auto start = html.find("content=\"", tpos);
    if (start != std::string_view::npos) {
      start += 9;
      auto end = html.find('"', start);
      if (end != std::string_view::npos)
        r.title = std::string(html.substr(start, end - start));
    }
  }
  auto dpos = html.find("og:description");
  if (dpos != std::string_view::npos) {
    auto start = html.find("content=\"", dpos);
    if (start != std::string_view::npos) {
      start += 9;
      auto end = html.find('"', start);
      if (end != std::string_view::npos)
        r.description = std::string(html.substr(start, end - start));
    }
  }
  auto ipos = html.find("og:image");
  if (ipos != std::string_view::npos) {
    auto start = html.find("content=\"", ipos);
    if (start != std::string_view::npos) {
      start += 9;
      auto end = html.find('"', start);
      if (end != std::string_view::npos)
        r.image_url = std::string(html.substr(start, end - start));
    }
  }
  return r;
}

}  // namespace progressive::urlpreview
