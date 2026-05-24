#pragma once
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <string_view>

#include "../util/cache.hpp"

namespace progressive::sync {

class LazyMemberCache {
public:
  bool has_sent(std::string_view user_id, std::string_view state_key, std::string_view event_id);
  void mark_sent(std::string_view user_id, std::string_view state_key, std::string_view event_id);
  void clear_user(std::string_view user_id);

private:
  std::mutex mutex_;
  // user_id -> LruCache<state_key -> event_id>
  std::map<std::string, util::LruCache<std::string>, std::less<>> user_caches_;
};

}  // namespace progressive::sync
