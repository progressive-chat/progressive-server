#pragma once
#include <chrono>
#include <condition_variable>
#include <functional>
#include <map>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

namespace progressive::worker {

using JobFunc = std::function<void()>;

class WorkerPool {
public:
  WorkerPool(int num_workers = 4);
  ~WorkerPool();
  void submit(JobFunc job);

private:
  void worker_loop();
  std::vector<std::thread> threads_;
  std::queue<JobFunc> jobs_;
  std::mutex mutex_;
  bool running_ = true;
};

}  // namespace progressive::worker
