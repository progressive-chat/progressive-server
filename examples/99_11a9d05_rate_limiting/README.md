# Step 99 — "feat: rate-limiting" (Conduit `11a9d05`)

Source: [`timokoesters/conduit@11a9d05`](https://github.com/timokoesters/conduit/commit/11a9d05)

This step adds a comprehensive rate-limiting system with configurable presets (PrivateSmall, PrivateMedium, PublicMedium, PublicLarge) and per-action limits.

## What changed vs step 98

| Rust change | C++ translation |
|---|---|
| Full rate-limiting system with presets and per-action limits | **Already implemented** in `rate_limiting.{hpp,cpp}` with `PrivateSmall` defaults |
| Configurable presets and per-action limits | **Already implemented** - `RateLimiter` with `PrivateSmall` defaults |

## Implementation details

Our `rate_limiting.{hpp,cpp}` implements a sliding-window rate limiter with:
- Per-action limits matching Conduit's PrivateSmall preset
- Sliding time window (60s default)
- Per-bucket tracking by `(Restriction, IP+token)`
- `M_LIMIT_EXCEEDED` response with `retry_after_ms`
- Test mode via `CONDUIT_RATE_LIMIT_TEST` env var

## Smoke test

Rate limiting works with default PrivateSmall limits.