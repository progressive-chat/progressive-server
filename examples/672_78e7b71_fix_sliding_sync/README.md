# Step 672 — "fix: better sliding sync" (Conduit `78e7b71`)

Source: [`timokoesters/conduit@78e7b71`](https://github.com/timokoesters/conduit/commit/78e7b71) (2023-07)

## What changed vs step 671

| Rust change | C++ translation |
|---|---|
| Fix: better sliding sync. Added prev_batch to room response in sliding sync. | **Translated** — Added prev_batch to each room's sliding sync response. |

## Implementation details

- **main.cpp (POST /_matrix/client/v4/sync)**: Added `prev_batch` field to each room's response:
  - Extracts prev_batch from the first timeline PDU (simplified: uses `since` as fallback)
  - Returns `prev_batch` in room object alongside timeline, state, name, limited

This mirrors Conduit's fix where `prev_batch` is computed from the first PDU in the timeline.

**Status:** Real implementation (simplified - uses `since` as prev_batch fallback).

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```