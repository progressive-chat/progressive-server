// waiting_servers.hpp — tracker for federation servers with pending requests
// (NEW in ab33236: fix: don't send new requests to servers if we are already waiting)

#pragma once

#include <chrono>
#include <mutex>
#include <set>
#include <string>

namespace federation {

// Tracks servers that have pending federation requests
// Prevents sending duplicate requests to servers that are already processing
class WaitingServersTracker {
 public:
  // Try to add a server to the waiting set
  // Returns true if the server was added (not already waiting)
  // Returns false if the server is already waiting
  bool try_add(const std::string& server) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::steady_clock::now();
    cleanup_expired_locked(now);
    return waiting_servers_.insert(server).second;
  }

  // Remove a server from the waiting set
  void remove(const std::string& server) {
    std::lock_guard<std::mutex> lock(mutex_);
    waiting_servers_.erase(server);
  }

  // Check if a server is currently waiting
  bool is_waiting(const std::string& server) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::steady_clock::now();
    cleanup_expired_locked(now);
    return waiting_servers_.count(server) > 0;
  }

  // Get the number of servers currently waiting
  size_t size() {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::steady_clock::now();
    cleanup_expired_locked(now);
    return waiting_servers_.size();
  }

 private:
  // Remove expired entries (older than 60 seconds)
  void cleanup_expired_locked(std::chrono::steady_clock::time_point now) {
    auto cutoff = now - std::chrono::seconds(60);
    for (auto it = waiting_servers_.begin(); it != waiting_servers_.end();) {
      if (timestamps_[*it] < cutoff) {
        timestamps_.erase(*it);
        it = waiting_servers_.erase(it);
      } else {
        ++it;
      }
    }
  }

  std::mutex mutex_;
  std::set<std::string> waiting_servers_;
  std::map<std::string, std::chrono::steady_clock::time_point> timestamps_;
};

}  // namespace federation