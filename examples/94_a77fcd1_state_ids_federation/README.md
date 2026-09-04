# Step 94 — "feat: implement /state_ids and fix federation stuff" (Conduit `a77fcd1`)

Source: [`timokoesters/conduit@a77fcd1`](https://github.com/timokoesters/conduit/commit/a77fcd1) (2021-03-18)

## What changed vs step 93

| Rust change | C++ translation |
|---|---|
| **Implement /state_ids** | **Partial** — Basic endpoint exists, needs shortstatehash integration |
| **Fix federation stuff** | **Partial** — Limit prev_events to 20 |

## Implementation details

1. **Added `/state_ids` federation endpoint** in main.cpp:
   - `GET /_matrix/federation/v1/state_ids/{room_id}/{event_id}`
   - Returns auth_chain_ids and pdu_ids
   - Uses room_state for auth chain (simplified)

2. **Limited prev_events to 20** in pdu_append (matching Conduit's truncate to 20)

**Missing/Partial:**
- No `pdu_shortstatehash` method (needs shortstatehash infrastructure from step 93)
- No `state_full_ids` with shortstatehash (needs shortstatehash infrastructure from step 93)
- Current implementation uses simplified auth chain (room_state instead of full auth chain)

**Status:** Partial implementation — basic endpoint works, needs shortstatehash infrastructure from step 93 for full compatibility

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```