#pragma once
#include <map>
#include <mutex>
#include <queue>
#include <string>
#include <string_view>

#include "../storage/database.hpp"

namespace progressive::federation {

class BackfillOrchestrator {
public:
  explicit BackfillOrchestrator(storage::DatabasePool& db);
  void check_and_backfill(std::string_view room_id);
  void enqueue_backfill(std::string_view room_id, std::string_view destination);

private:
  storage::DatabasePool& db_;
  std::map<std::string, std::queue<std::string>> backfill_queue_;
  std::mutex mutex_;
};

}  // namespace progressive::federation
