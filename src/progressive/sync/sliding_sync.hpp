#pragma once
#include <map>
#include <set>
#include <string>
#include <string_view>

#include "../storage/database.hpp"
#include "../util/time.hpp"

namespace progressive::sync {

struct SlidingSyncConnection {
  std::string conn_id;
  std::string user_id;
  std::string pos;
  std::set<std::string> rooms;
  int64_t created_ts;
  int64_t updated_ts;
};

class SlidingSyncEngine {
public:
  SlidingSyncEngine(storage::DatabasePool& db);
  nlohmann::json sync(const std::string& conn_id, const std::string& user_id,
                      const nlohmann::json& req);
  void add_room(const std::string& conn_id, const std::string& room_id);

private:
  storage::DatabasePool& db_;
  std::map<std::string, SlidingSyncConnection, std::less<>> connections_;
};

}  // namespace progressive::sync
