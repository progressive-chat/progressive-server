#include "lock.hpp"

#include <thread>

namespace progressive::worker {

bool WorkerLock::acquire(std::string_view lock_name, int timeout_ms) {
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

void WorkerLock::release(std::string_view lock_name) {
  std::lock_guard lock(mutex_);
  locks_.erase(std::string(lock_name));
}

}  // namespace progressive::worker
