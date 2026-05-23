#pragma once
#include <map>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <tuple>

#include "../util/cache.hpp"

namespace progressive::state {

using StateKey = std::tuple<std::string, std::string>;
using StateMap = std::map<StateKey, std::string>;

class StateGroupStore {
public:
  StateGroupStore();

  int64_t get_or_create_group(const StateMap& state);
  StateMap get_state(int64_t group_id);
  void clear_cache();

private:
  util::LruCache<StateMap> cache_{500, 300};  // 500 entries, 5min TTL
  int64_t next_group_id_ = 1;
};

}  // namespace progressive::state
