# Step 132 — "Add closest_parent method to Rooms Db insert in order /send pdus" (Conduit `db8a0c5`)

Source: [`timokoesters/conduit@db8a0c5`](https://github.com/timokoesters/conduit/commit/db8a0c5) (2020-12)

## What changed vs step 131

| Rust change | C++ translation |
|---|---|
| Adds the `closest_parent` method to Rooms DB. Used in `/send` PDU insertion to find the correct ordering of events. | **Translated** — Implemented `get_closest_parent` method with `ClosestParent` variant type. |

## Implementation details

1. **Added `ClosestParent` variant type** in data.hpp:
   - `ClosestParentAppend` — last event is in prev_events
   - `ClosestParentInsert(count)` — found common ancestor at position count

2. **Implemented `get_closest_parent` method** in data.cpp:
   - Checks if the last event in the room matches one of the incoming prev_events (returns `ClosestParentAppend`)
   - Otherwise walks back through prev_ids to find a known ancestor
   - Returns `ClosestParentInsert(count)` with the pdu_count if found
   - Returns `std::nullopt` if no common ancestor found

3. **Added helper methods** in data.cpp:
   - `get_pdu_id(event_id)` — looks up event_id in eventid_pduid tree
   - `pdu_count(pdu_id)` — returns the sequence count for a PDU (stub implementation)

4. **Added helper types** in data.hpp:
   - `ClosestParentAppend` and `ClosestParentInsert` structs
   - `ClosestParent` variant type using `std::variant`

**Status:** Real implementation (core `closest_parent` logic implemented)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
