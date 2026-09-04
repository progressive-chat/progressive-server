# Step 67 — "Abstract event validation/fetching, add outlier and signing key DB trees" (Conduit `851eb55`)

Source: [`timokoesters/conduit@851eb55`](https://github.com/timokoesters/conduit/commit/851eb55) (2021-01-14)

## What changed vs step 66

| Rust change | C++ translation |
|---|---|
| **Add outlier DB tree** | **Translated** — Added `eventid_outlierpdu` tree |
| **Add signing key DB tree** | **Translated** — Added `servertimeout_signingkey` tree |

## Implementation details

1. **Added `eventid_outlierpdu` tree** — Maps event_id to outlier PDU for events that haven't passed state resolution yet
2. **Added `servertimeout_signingkey` tree** — Stores signing key for server timeout operations

**Status:** Real implementation (database trees added). The event validation abstraction and server_server refactor are not yet implemented in C++.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```