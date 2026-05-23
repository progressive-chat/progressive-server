#pragma once
#include <map>
#include <mutex>
#include <string>
#include <string_view>

namespace progressive::worker {

class WorkerLock {
public:
  bool acquire(std::string_view lock_name, int timeout_ms = 5000);
  void release(std::string_view lock_name);

private:
  std::map<std::string, bool, std::less<>> locks_;
  std::mutex mutex_;
};

}  // namespace progressive::worker
