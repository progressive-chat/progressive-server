#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <tuple>

namespace progressive {

using StateKey = std::tuple<std::string, std::string>;

template <typename T>
using StateMap = std::map<StateKey, T>;

struct StateFilter {
  std::map<std::string, bool> types;
  bool include_others = true;

  static StateFilter all() { return {}; }
};

struct StreamToken {
  std::string room_key;
  uint64_t presence_key = 0;
  uint64_t typing_key = 0;
  uint64_t receipt_key = 0;

  static StreamToken from_string(std::string_view s);
  std::string to_string() const;
};

}  // namespace progressive
