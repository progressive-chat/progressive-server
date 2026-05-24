#include "replication.hpp"

#include <thread>

#include "../util/time.hpp"

namespace progressive::worker {

// ReplicationStream
ReplicationStream::ReplicationStream(StreamType type) : type_(type) {}

int64_t ReplicationStream::current_position() const {
  return position_;
}

void ReplicationStream::advance(int64_t position) {
  position_ = position;
}

bool ReplicationStream::has_changed_since(int64_t token) const {
  return position_ > token;
}

// StreamPositionStore
void StreamPositionStore::update_position(std::string_view worker_name, StreamType type,
                                          int64_t position) {
  std::lock_guard lock(mutex_);
  positions_[std::string(worker_name)][type] = position;
}

int64_t StreamPositionStore::get_position(std::string_view worker_name, StreamType type) const {
  std::lock_guard lock(mutex_);
  auto wit = positions_.find(std::string(worker_name));
  if (wit == positions_.end())
    return 0;
  auto tit = wit->second.find(type);
  return tit != wit->second.end() ? tit->second : 0;
}

std::map<StreamType, int64_t> StreamPositionStore::get_all_positions(
    std::string_view worker_name) const {
  std::lock_guard lock(mutex_);
  auto wit = positions_.find(std::string(worker_name));
  if (wit != positions_.end())
    return wit->second;
  return {};
}

void StreamPositionStore::clear() {
  std::lock_guard lock(mutex_);
  positions_.clear();
}

// WorkerLockManager
bool WorkerLockManager::acquire(std::string_view lock_name, int timeout_ms) {
  std::string name(lock_name);
  auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);

  while (std::chrono::steady_clock::now() < deadline) {
    std::lock_guard lock(mutex_);
    if (!locks_[name]) {
      locks_[name] = true;
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  return false;
}

void WorkerLockManager::release(std::string_view lock_name) {
  std::lock_guard lock(mutex_);
  locks_.erase(std::string(lock_name));
}

bool WorkerLockManager::is_locked(std::string_view lock_name) const {
  std::lock_guard lock(mutex_);
  auto it = locks_.find(std::string(lock_name));
  return it != locks_.end() && it->second;
}

// WorkerRegistry
void WorkerRegistry::register_worker(std::string_view name, WorkerType type) {
  std::lock_guard lock(mutex_);
  workers_[std::string(name)] = type;
}

void WorkerRegistry::unregister_worker(std::string_view name) {
  std::lock_guard lock(mutex_);
  workers_.erase(std::string(name));
}

std::set<std::string> WorkerRegistry::get_workers_of_type(WorkerType type) const {
  std::lock_guard lock(mutex_);
  std::set<std::string> result;
  for (auto& [name, wt] : workers_)
    if (wt == type)
      result.insert(name);
  return result;
}

std::set<std::string> WorkerRegistry::get_all_workers() const {
  std::lock_guard lock(mutex_);
  std::set<std::string> result;
  for (auto& [name, _] : workers_)
    result.insert(name);
  return result;
}

}  // namespace progressive::worker
