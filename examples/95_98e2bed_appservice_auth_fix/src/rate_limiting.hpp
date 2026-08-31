// rate_limiting.hpp — sliding-window rate limiter (translation of Conduit's
// 11a9d053b0 "feat: rate-limiting"). Conduit models this with an elaborate
// preset/shadow config DSL (conduit-config/src/rate_limiting.rs, ~825 lines)
// and a service (conduit/src/service/rate_limiting/mod.rs, ~579 lines). Our
// single-server port has no Conduit config system, so we keep the *observable
// behaviour* faithful: requests are bucketed per (Restriction action, IP+token)
// in a sliding time window, and overflow returns M_LIMIT_EXCEEDED with
// retry_after_ms. Per-action limits default to Conduit's PrivateSmall preset.

#pragma once

#include <chrono>
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <string>

namespace httplib {
struct Request;
}

namespace rate_limiting {

enum class Restriction {
  Registration,
  Login,
  RegistrationTokenValidity,
  SendEvent,
  Join,
  Invite,
  Knock,
  SendReport,
  CreateAlias,
  MediaDownload,
  MediaCreate,
  FederationJoin,
  FederationKnock,
  FederationInvite,
  FederationTransaction,
  FederationMediaDownload,
  Unknown,
};

struct RequestLimitation {
  int64_t timeframe_sec;
  uint64_t burst_capacity;
};

// Classify an incoming request into the action bucket it should count against.
Restriction classify(const struct httplib::Request& req);

class RateLimiter {
 public:
  RateLimiter();

  // Returns true if the request is allowed. On denial, `retry_after_ms_out` is
  // set to how long the caller must wait before retrying.
  bool check(Restriction r, const std::string& bucket_key,
             int64_t& retry_after_ms_out);

 private:
  RequestLimitation limit_for(Restriction r) const;

  mutable std::mutex mu_;
  std::map<std::pair<Restriction, std::string>, std::deque<int64_t>> buckets_;

  // When the CONDUIT_RATE_LIMIT_TEST env var is set to a positive integer N,
  // every action is limited to N requests per 60s. This is only for verifying
  // the limiter end-to-end; production uses the per-action defaults below.
  uint64_t test_burst_ = 0;
};

}  // namespace rate_limiting
