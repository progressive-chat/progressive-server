#include "ratelimit.hpp"

#include <algorithm>

#include "../util/time.hpp"

namespace progressive::ratelimit {

RateLimiter::RateLimiter(double rate_per_sec, double burst)
    : rate_per_sec_(rate_per_sec), burst_(burst) {}

void RateLimiter::set_rate(double rate_per_sec, double burst) {
  rate_per_sec_ = rate_per_sec;
  burst_ = burst;
}

void RateLimiter::refill(Bucket& b) const {
  int64_t now = util::now_ms();
  int64_t elapsed = now - b.last_refill_ms;
  b.tokens = std::min(burst_, b.tokens + (elapsed / 1000.0) * rate_per_sec_);
  b.last_refill_ms = now;
}

bool RateLimiter::allow(std::string_view key) {
  std::lock_guard lock(mutex_);

  auto it = buckets_.find(key);
  if (it == buckets_.end()) {
    buckets_[std::string(key)] = {burst_ - 1, static_cast<int64_t>(util::now_ms())};
    return true;
  }

  refill(it->second);
  if (it->second.tokens >= 1.0) {
    it->second.tokens -= 1.0;
    return true;
  }
  return false;
}

bool EndpointRateLimiter::allow(std::string_view endpoint, std::string_view ip) {
  std::lock_guard lock(mutex_);
  std::string ep(endpoint);
  auto it = limiters_.find(ep);
  if (it == limiters_.end()) {
    limiters_.try_emplace(ep, 100.0, 200.0);
    it = limiters_.find(ep);
  }
  return it->second.allow(ip);
}

void EndpointRateLimiter::set_limit(std::string_view endpoint, double rate, double burst) {
  std::lock_guard lock(mutex_);
  limiters_.erase(std::string(endpoint));
  limiters_.try_emplace(std::string(endpoint), rate, burst);
}

}  // namespace progressive::ratelimit
