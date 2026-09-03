# Step 625 — "feat: respect history visibility" (Conduit `10fa686`)

Source: [`timokoesters/conduit@10fa686`](https://github.com/timokoesters/conduit/commit/10fa686) (2023-03)

## What changed vs step 624

| Rust change | C++ translation |
|---|---|
| Feat: respect history visibility. History visibility rules for room events. 8 files changed. MAJOR feature. | **Translated** — Added history visibility checks for room events. |

## Implementation details

- **data.hpp/data.cpp**: Added methods:
  - `room_history_visibility(room_id)` - gets the history_visibility setting (default: "shared")
  - `user_can_see_state_events(user_id, room_id)` - checks if user can see state events in a room
  - `user_can_see_event(user_id, room_id, event_id)` - checks if user can see a specific event

- **main.cpp**: Updated routes to use history visibility checks:
  - `/rooms/{room_id}/members` - uses `user_can_see_state_events`
  - `/rooms/{room_id}/state/{type}[/{state_key}]` - uses `user_can_see_state_events`
  - `/rooms/{room_id}/event/{event_id}` - uses `user_can_see_event` with proper error message

- History visibility levels handled:
  - `world_readable` - anyone can see
  - `shared` (default) - only joined members can see
  - `invited` - only invited members can see (simplified to joined for now)
  - `joined` - only joined members can see

**Status:** Real implementation (simplified - uses current state's history_visibility rather than event's state hash).

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```