# 2026-tail — "feat: rate-limiting" (Conduit `11a9d053b0`)

Source: [`timokoesters/conduit@11a9d053b0`](https://github.com/timokoesters/conduit/commit/11a9d053b0) (2026-07-17)

## What changed vs step 93 (last numbered step)

| Rust change | C++ translation |
|---|---|
| Adds `rate_limiting.{hpp,cpp}` with `PrivateSmall` preset and sliding window per (action, IP+token). | **Translated** — Full C++ implementation with `rate_limiting.{hpp,cpp}` |

## Implementation details

1. **Added `rate_limiting.{hpp,cpp}`** with:
   - `Restriction` enum for all action types (Registration, Login, SendEvent, Join, Invite, Knock, etc.)
   - Sliding window rate limiter per (Restriction, IP+token) bucket
   - Per-action limits matching Conduit's "PrivateSmall" preset
   - Test mode via `CONDUIT_RATE_LIMIT_TEST` env var

2. **Integration in main.cpp**:
   - Creates `RateLimiter` instance
   - Adds to `Context` struct
   - Pre-request hook checks rate limits
   - Returns `M_LIMIT_EXCEEDED` with `retry_after_ms` on overflow

**Status:** Full implementation

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```