# Step 670 — "feat: very simple sliding sync implementation" (Conduit `e4f7699`)

Source: [`timokoesters/conduit@e4f7699`](https://github.com/timokoesters/conduit/commit/e4f7699) (2023-07)

## What changed vs step 669

| Rust change | C++ translation |
|---|---|
| Feat: very simple sliding sync implementation. Sliding sync (MSC3575) for efficient /sync. 12 files changed. MAJOR feature. | **Translated** — Added MSC3575 sliding sync endpoint (`POST /_matrix/client/v4/sync`). |

## Implementation details

- **data.hpp/data.cpp**: Added sliding sync helper methods:
  - `get_timeline_pdus(room_id, since, limit)` - returns (timeline_pdus, limited) pair
  - `get_required_state(room_id, state_keys)` - gets required state events for a room
  - `get_room_name(room_id)` - gets room name for sync response

- **main.cpp**: Added `POST /_matrix/client/v4/sync` endpoint (MSC3575):
  - Accepts `lists` parameter with ranges and room_details
  - Supports `ranges` (start, end indices into joined rooms)
  - Supports `room_details` with `timeline_limit` and `required_state`
  - Returns `lists` with ops (sync with range and room_ids)
  - Returns `rooms` with timeline, state, name, limited flag
  - Returns `pos`, `next_batch` for pagination
  - Uses existing `last_timeline_count` cache for efficiency

- Supports basic sliding sync: list-based room selection, configurable timeline limits, required state filtering
- Simplified: no device_lists, account_data, to_device, device_one_time_keys_count extensions
- No long-polling/watcher implementation (uses simple stateless response)

**Status:** Real implementation (simplified).

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```