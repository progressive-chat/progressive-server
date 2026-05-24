#include "backfill.hpp"

#include <iostream>

#include "../util/time.hpp"

namespace progressive::federation {

BackfillOrchestrator::BackfillOrchestrator(storage::DatabasePool& db) : db_(db) {}

void BackfillOrchestrator::check_and_backfill(std::string_view room_id) {
  std::lock_guard lock(mutex_);
  auto& q = backfill_queue_[std::string(room_id)];
  if (q.empty())
    return;

  std::string dest = q.front();
  q.pop();
  std::cout << "[backfill] requesting backfill for " << room_id << " from " << dest << "\n";

  // In production: make HTTP GET /backfill/{roomId} to dest
  // For now: log and mark as processed
}

void BackfillOrchestrator::enqueue_backfill(std::string_view room_id,
                                            std::string_view destination) {
  std::lock_guard lock(mutex_);
  backfill_queue_[std::string(room_id)].push(std::string(destination));
}

}  // namespace progressive::federation
