#include "pool.hpp"

#include <condition_variable>

namespace progressive::worker {

WorkerPool::WorkerPool(int n) {
  for (int i = 0; i < n; i++)
    threads_.emplace_back(&WorkerPool::worker_loop, this);
}

WorkerPool::~WorkerPool() {
  running_ = false;
  for (auto& t : threads_)
    t.join();
}

void WorkerPool::submit(JobFunc job) {
  std::lock_guard lock(mutex_);
  jobs_.push(std::move(job));
}

void WorkerPool::worker_loop() {
  while (running_) {
    JobFunc job;
    {
      std::lock_guard lock(mutex_);
      if (!jobs_.empty()) {
        job = std::move(jobs_.front());
        jobs_.pop();
      }
    }
    if (job)
      job();
    else
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
}

}  // namespace progressive::worker
