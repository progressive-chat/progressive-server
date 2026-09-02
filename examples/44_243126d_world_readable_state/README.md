# Step 44 — "Allow reading state if history_visibility is world readable" (Conduit `243126d`)

Source: [`timokoesters/conduit@243126d`](https://github.com/timokoesters/conduit/commit/243126d) (2020-10-18)

## What changed vs step 43

| Rust change | C++ translation |
|---|---|
| **Added check for `HistoryVisibility::WorldReadable`** in `get_state_events_route` | **Translated** — Check world_readable in state endpoint |
| **Added check for `HistoryVisibility::WorldReadable`** in `get_state_events_for_key_route` | **Translated** — Check world_readable in state key endpoint |
| **Added check for `HistoryVisibility::WorldReadable`** in `get_state_events_for_empty_key_route` | **Translated** — Check world_readable in empty key state endpoint |

## Implementation details

1. **Users not in the room** can now read state if the room's `history_visibility` is set to `WorldReadable`
2. **Three state endpoints** updated:
   - `GET /_matrix/client/r0/rooms/{roomId}/state`
   - `GET /_matrix/client/r0/rooms/{roomId}/state/{type}/{stateKey}`
   - `GET /_matrix/client/r0/rooms/{roomId}/state/{type}`
3. **Permission check** updated: if user is not joined, check if room is world_readable before denying access

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
