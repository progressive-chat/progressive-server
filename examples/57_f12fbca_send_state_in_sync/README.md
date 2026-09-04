# Step 57 — "fix: send state in /sync" (Conduit `f12fbca`)

Source: [`timokoesters/conduit@f12fbca`](https://github.com/timokoesters/conduit/commit/f12fbca) (2020-12-22)

## What changed vs step 56

| Rust change | C++ translation |
|---|---|
| **Send state events in /sync** | **Translated** — Added `state` field to `SyncResponse` with `events` vector |
| **Fix membership changes display** | **Translated** — State events now include `unsigned.prev_content` for membership changes |
| **Send state in initial sync** | **Translated** — State events sent in initial and incremental sync |
| **Add `unsigned.prev_content` to state events** | **Translated** — State events now include previous content for membership changes |

## Implementation details

1. **data.hpp/data.cpp**: Added state resolution methods:
   - `append_state_pdu()` — generates new StateHash and stores state mappings
   - `new_state_hash_id()` — computes SHA-256 hash from current state
   - `current_state_pduids()` — returns all `(type,key) -> pdu_id` pairs
   - `pdu_statehash()` — gets StateHash for a PDU
   - `get_statemap_by_hash()` — builds state map from StateHash
   - `prev_state_hash()` — walks back through state hash chain
   - `get_prev_content()` — efficiently retrieves previous content for state events

2. **database.hpp/cpp**: Added state resolution trees:
   - `stateid_pduid` — StateHash + (EventType, StateKey) → pdu_id
   - `pduid_statehash` — PDU id → StateHash
   - `roomid_statehash` — room_id → latest StateHash

3. **data.cpp (pdu_append)**: 
   - Calls `append_state_pdu()` for state events
   - Uses `get_prev_content()` for efficient `unsigned.prev_content` lookup

4. **ruma_wrapper.hpp**: Added `state` field to `SyncResponse` with `events` vector

4. **main.cpp (sync_route)**: 
   - Initial sync: sends all current state events
   - Incremental sync: sends current state events
   - State events are added to `joined.state.events` for each room

**Status:** Real implementation (core state in sync functionality)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```