# Step 52 — "Fix get_closest_parent and cleanup federation/send/:txn" (Conduit `acd144e`)

Source: [`timokoesters/conduit@acd144e`](https://github.com/timokoesters/conduit/commit/acd144e) (2020-12-05)

## What changed vs step 50

| Rust change | C++ translation |
|---|---|
| **`get_closest_parent` now takes `room_id` parameter** | **Translated** — Updated signature and implementation |
| **Changed `pduid_pdu.last()` to `scan_prefix(room).last()`** | **Translated** — Uses room-scoped scan |
| **Added room existence check in `/send/txn`** | **Translated** — Returns error for unknown rooms |
| **Updated `get_closest_parent` calls** to pass `room_id` | **Translated** — Updated call sites |
| **Changed `&db.sending` to `&db.admin`** | **Translated** — Updated federation sending |

## Implementation details

1. **`get_closest_parent` signature**: Now takes `room_id` as first parameter
2. **Room-scoped scan**: Uses `scan_prefix(room.as_bytes()).last()` instead of `.last()`
3. **Room existence check**: Added early return for unknown rooms in `/send/txn`
4. **Updated call sites**: `get_closest_parent(room_id, &pdu.prev_events, &their_current_state)`

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
