#include "state_group.hpp"

#include <functional>

namespace progressive::state {

StateGroupStore::StateGroupStore() = default;

int64_t StateGroupStore::get_or_create_group(const StateMap& state) {
  // Hash the state to deduplicate
  std::string hash_key;
  for (auto& [k, v] : state) {
    hash_key += v + "@";
  }

  auto cached = cache_.get(hash_key);
  if (cached.has_value())
    return ++next_group_id_;

  // Check if we already have this exact state
  // In production, this queries state_groups_state table
  int64_t gid = next_group_id_++;
  cache_.put(hash_key, state);
  return gid;
}

StateMap StateGroupStore::get_state(int64_t group_id) {
  // In production, this queries state_groups_state table
  return {};
}

void StateGroupStore::clear_cache() {
  cache_.clear();
}

}  // namespace progressive::state
