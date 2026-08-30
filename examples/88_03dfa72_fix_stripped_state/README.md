# Step 88 — "fix: don't lookup create event when converting stripped state" (Conduit `03dfa72`)

Source: [`timokoesters/conduit@03dfa72`](https://github.com/timokoesters/conduit/commit/03dfa72)

This step fixes a redundant room ID lookup in Conduit's `convert_stripped_state` function. Previously it took a `room_id` and looked up the room version rules internally; now it takes `RoomVersionRules` directly.

## What changed vs step 86

| Rust change | C++ translation |
|---|---|
| `convert_stripped_state(stripped_state, &room_id)` → `convert_stripped_state(stripped_state, &rules)` | **No-op** — our implementation doesn't have a `convert_stripped_state` function |

## Implementation details

Our translation never implemented a `convert_stripped_state` function. We directly push PDU JSON strings to the `stripped_state` vector in `sync_route` (for invited/knocked rooms). There was no room ID lookup to remove, so this commit is effectively a no-op for our translation.

## Smoke test

No behavioral change — existing invite/knock stripped state behavior unchanged.