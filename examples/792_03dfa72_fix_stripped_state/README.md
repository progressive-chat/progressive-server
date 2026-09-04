# Step 792 — fix_stripped_state

Source: [`timokoesters/conduit@03dfa72`](https://github.com/timokoesters/conduit/commit/03dfa72) (2025-08-16)

## What changed vs step 791

| Rust change | C++ translation |
|---|---|
| Skips the create event lookup when converting stripped state to m.room.member events. Passes room version rules instead of room_id. | **Requires federation** — Our federation invite/knock doesn't have this optimization yet. |

## Implementation details

This fix changes `convert_stripped_state` to accept room version rules directly instead of looking them up from the room_id (which required a create event lookup):

1. **Membership routes** (knock, invite): Pass `rules` instead of `room_id`
2. **Federation invite creation**: Pass `rules` instead of `room_id`
3. **convert_stripped_state utility**: Now takes `RoomVersionRules` directly, avoiding create event lookup

**Status:** Requires federation implementation (step 29+). Our federation doesn't have this optimization yet.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```