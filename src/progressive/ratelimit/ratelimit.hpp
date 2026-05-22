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

  bool allow(std::string_view key);
  void set_rate(double rate_per_sec, double burst);

private:
  void refill(Bucket& b) const;
  double rate_per_sec_;
  double burst_;
  std::map<std::string, Bucket, std::less<>> buckets_;
  std::mutex mutex_;
};

}  // namespace progressive::ratelimit
