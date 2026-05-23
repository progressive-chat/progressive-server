#pragma once
#include <atomic>
#include <map>
#include <string>

namespace progressive::util {

class StreamChangeCache {
public:
  StreamChangeCache() = default;
  bool has_changed(std::string_view room_id, uint64_t since_token) {
    auto it = rooms_.find(std::string(room_id));
    if (it == rooms_.end())
      return false;
    return it->second > since_token;
  }
  void mark_changed(std::string_view room_id, uint64_t stream_ordering) {
    rooms_[std::string(room_id)] = stream_ordering;
  }
  void clear() { rooms_.clear(); }

private:
  std::map<std::string, uint64_t, std::less<>> rooms_;
};

}  // namespace progressive::util
