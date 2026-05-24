#include "lazy_members.hpp"

namespace progressive::sync {

bool LazyMemberCache::has_sent(std::string_view user_id, std::string_view state_key,
                               std::string_view event_id) {
  std::lock_guard lock(mutex_);
  auto it = user_caches_.find(std::string(user_id));
  if (it == user_caches_.end())
    return false;
  auto cached = it->second.get(std::string(state_key));
  return cached.has_value() && *cached == event_id;
}

void LazyMemberCache::mark_sent(std::string_view user_id, std::string_view state_key,
                                std::string_view event_id) {
  std::lock_guard lock(mutex_);
  auto& cache = user_caches_[std::string(user_id)];
  cache.put(std::string(state_key), std::string(event_id));
}

void LazyMemberCache::clear_user(std::string_view user_id) {
  std::lock_guard lock(mutex_);
  user_caches_.erase(std::string(user_id));
}

}  // namespace progressive::sync
