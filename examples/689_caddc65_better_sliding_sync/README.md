# Step 689 — "slightly better sliding sync" (Conduit `caddc65`)

Source: [`timokoesters/conduit@caddc65`](https://github.com/timokoesters/conduit/commit/caddc65) (2023-07)

## What changed vs step 688

| Rust change | C++ translation |
|---|---|
| Slightly better sliding sync. Sliding sync improvements. 4 files changed. | **Requires step 670/672** — This adds major improvements to sliding sync (MSC3575). |

## Implementation details

This Conduit commit adds significant sliding sync improvements:

1. **Connection caching**: `conn_id` support with `forget_sync_request_connection` and cached requests
2. **Known rooms tracking**: `update_sync_request_with_cache` and `update_sync_known_rooms` for efficient sync
3. **Room subscriptions**: Support for `room_subscriptions` in addition to lists
4. **Better prev_batch**: Falls back to `since` when no timeline PDUs
5. **Improved room names**: Falls back to member display names when room name not set
6. **Initial flag**: Uses `since == 0` instead of tracking initial sync
7. **Connection management**: New `users::Service::connections` with `SlidingSyncCache`

**Status:** Requires step 670/672 (sliding sync implementation) as a base. This would be a major enhancement on top of our basic sliding sync.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```