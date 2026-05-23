#pragma once
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <string_view>

namespace progressive::ratelimit {

struct Bucket {
  double tokens;
  int64_t last_refill_ms;
};

class RateLimiter {
public:
  RateLimiter(double rate_per_sec = 10.0, double burst = 20.0);
  RateLimiter(const RateLimiter&) = delete;
  RateLimiter& operator=(const RateLimiter&) = delete;

  bool allow(std::string_view key);
  void set_rate(double rate_per_sec, double burst);

private:
  void refill(Bucket& b) const;
  double rate_per_sec_;
  double burst_;
  std::map<std::string, Bucket, std::less<>> buckets_;
  std::mutex mutex_;
};

class EndpointRateLimiter {
public:
  EndpointRateLimiter() = default;
  bool allow(std::string_view endpoint, std::string_view ip);
  void set_limit(std::string_view endpoint, double rate, double burst);

private:
  std::map<std::string, RateLimiter, std::less<>> limiters_;
  std::mutex mutex_;
};

}  // namespace progressive::ratelimit
