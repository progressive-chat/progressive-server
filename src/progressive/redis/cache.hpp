#pragma once
#include <atomic>
#include <map>
#include <string>
#include <string_view>

namespace progressive::redis {

struct RedisConfig {
  std::string host = "127.0.0.1";
  int port = 6379;
  std::string password;
  int db = 0;
  bool enabled = false;
};

class RedisCache {
public:
  std::string get(std::string_view key) {
    auto it = store_.find(std::string(key));
    return it != store_.end() ? it->second : "";
  }
  void set(std::string_view key, std::string_view value, int ttl = 0) {
    store_[std::string(key)] = std::string(value);
  }
  void del(std::string_view key) { store_.erase(std::string(key)); }
  void publish(std::string_view channel, std::string_view msg) { get("_pubsub"); }

private:
  std::map<std::string, std::string, std::less<>> store_;
  std::atomic<uint64_t> hits_{0}, misses_{0};
};

}  // namespace progressive::redis
