#pragma once
#include <chrono>
#include <list>
#include <map>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>

namespace progressive::util {

template <typename V>
class LruCache {
public:
  LruCache(size_t max_size = 1000, int ttl_seconds = 60)
      : max_size_(max_size), ttl_(std::chrono::seconds(ttl_seconds)) {}

  std::optional<V> get(std::string_view key) {
    std::shared_lock lock(mutex_);
    auto it = map_.find(std::string(key));
    if (it == map_.end())
      return std::nullopt;
    auto& entry = it->second;
    auto now = std::chrono::steady_clock::now();
    if (now - entry.second > ttl_) {
      lock.unlock();
      std::unique_lock wlock(mutex_);
      map_.erase(it->first);
      return std::nullopt;
    }
    return entry.first;
  }

  void put(std::string_view key, V value) {
    std::unique_lock lock(mutex_);
    std::string k(key);
    auto it = map_.find(k);
    if (it != map_.end()) {
      it->second = {std::move(value), std::chrono::steady_clock::now()};
      return;
    }
    if (map_.size() >= max_size_) {
      auto oldest = map_.begin();
      for (auto i = map_.begin(); i != map_.end(); ++i)
        if (i->second.second < oldest->second.second)
          oldest = i;
      map_.erase(oldest);
    }
    map_[k] = {std::move(value), std::chrono::steady_clock::now()};
  }

  void clear() {
    std::unique_lock lock(mutex_);
    map_.clear();
  }
  size_t size() const {
    std::shared_lock lock(mutex_);
    return map_.size();
  }

private:
  size_t max_size_;
  std::chrono::seconds ttl_;
  mutable std::shared_mutex mutex_;
  std::map<std::string, std::pair<V, std::chrono::steady_clock::time_point>, std::less<>> map_;
};

}  // namespace progressive::util
