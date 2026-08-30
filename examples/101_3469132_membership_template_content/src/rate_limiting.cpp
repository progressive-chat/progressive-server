// rate_limiting.cpp — see rate_limiting.hpp for the translation note.
#include "rate_limiting.hpp"

#include <httplib.h>

#include <cstdlib>

namespace rate_limiting {

static int64_t now_sec() {
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

RateLimiter::RateLimiter() {
  if (const char* test = std::getenv("CONDUIT_RATE_LIMIT_TEST")) {
    try {
      uint64_t v = static_cast<uint64_t>(std::stoull(test));
      if (v > 0) test_burst_ = v;
    } catch (...) {
    }
  }
}

static RequestLimitation default_limit(Restriction r) {
  // (timeframe seconds, burst capacity) — Conduit "PrivateSmall"-style defaults.
  switch (r) {
    case Restriction::Registration:              return {60, 5};
    case Restriction::Login:                     return {60, 10};
    case Restriction::RegistrationTokenValidity: return {60, 10};
    case Restriction::SendEvent:                 return {10, 30};
    case Restriction::Join:                      return {60, 20};
    case Restriction::Invite:                    return {60, 20};
    case Restriction::Knock:                     return {60, 20};
    case Restriction::SendReport:                return {60, 5};
    case Restriction::CreateAlias:               return {60, 20};
    case Restriction::MediaDownload:             return {10, 50};
    case Restriction::MediaCreate:               return {60, 20};
    case Restriction::FederationJoin:            return {10, 100};
    case Restriction::FederationKnock:           return {10, 100};
    case Restriction::FederationInvite:          return {10, 100};
    case Restriction::FederationTransaction:     return {10, 200};
    case Restriction::FederationMediaDownload:   return {10, 200};
    default:                                     return {10, 1000};
  }
}

RequestLimitation RateLimiter::limit_for(Restriction r) const {
  if (test_burst_ > 0) return {60, test_burst_};
  return default_limit(r);
}

bool RateLimiter::check(Restriction r, const std::string& bucket_key,
                        int64_t& retry_after_ms_out) {
  const RequestLimitation lim = limit_for(r);
  const int64_t now = now_sec();
  const int64_t window_start = now - lim.timeframe_sec;

  std::lock_guard<std::mutex> lk(mu_);
  auto& dq = buckets_[{r, bucket_key}];
  while (!dq.empty() && dq.front() < window_start) dq.pop_front();

  if (static_cast<int64_t>(dq.size()) >= static_cast<int64_t>(lim.burst_capacity)) {
    int64_t retry = (dq.front() + lim.timeframe_sec) - now;
    if (retry < 1) retry = 1;
    retry_after_ms_out = retry * 1000;
    return false;
  }
  dq.push_back(now);
  return true;
}

Restriction classify(const httplib::Request& req) {
  const std::string& p = req.path;

  if (p.find("/_matrix/federation/") != std::string::npos) {
    if (p.find("/send/") != std::string::npos) return Restriction::FederationTransaction;
    if (p.find("/invite") != std::string::npos) return Restriction::FederationInvite;
    if (p.find("/knock") != std::string::npos) return Restriction::FederationKnock;
    if (p.find("/make_join") != std::string::npos ||
        p.find("/send_join") != std::string::npos)
      return Restriction::FederationJoin;
    if (p.find("/media") != std::string::npos) return Restriction::FederationMediaDownload;
    return Restriction::Unknown;
  }

  if (req.method == "POST") {
    if (p.find("/register") != std::string::npos) return Restriction::Registration;
    if (p.find("/login") != std::string::npos) return Restriction::Login;
    if (p.find("/send") != std::string::npos) return Restriction::SendEvent;
    if (p.find("/join") != std::string::npos) return Restriction::Join;
    if (p.find("/invite") != std::string::npos) return Restriction::Invite;
    if (p.find("/knock") != std::string::npos) return Restriction::Knock;
    if (p.find("/report") != std::string::npos) return Restriction::SendReport;
    if (p.find("/createAlias") != std::string::npos ||
        p.find("/directory/room") != std::string::npos)
      return Restriction::CreateAlias;
    if (p.find("/upload") != std::string::npos ||
        p.find("/media") != std::string::npos)
      return Restriction::MediaCreate;
  } else if (req.method == "GET") {
    if (p.find("/download") != std::string::npos ||
        p.find("/media") != std::string::npos ||
        p.find("/thumbnail") != std::string::npos)
      return Restriction::MediaDownload;
  }
  return Restriction::Unknown;
}

}  // namespace rate_limiting
