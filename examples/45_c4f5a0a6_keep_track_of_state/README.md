# Step 45 — "Keep track of State at event for state resolution" (Conduit `c4f5a0a6`)

Source: [`timokoesters/conduit@c4f5a0a6`](https://github.com/timokoesters/conduit/commit/c4f5a0a6) (2020-08-06)

## What changed vs step 44

| Rust change | C++ translation |
|---|---|
| **New database trees for state resolution** | **Translated** — Added `stateid_pduid`, `pduid_statehash`, `roomid_statehash` trees |
| **StateHash generation and tracking** | **Translated** — Implemented `append_state_pdu`, `new_state_hash_id`, `current_state_pduids` |
| **StateStore trait for state-res crate** | **Translated** — Core state resolution infrastructure |
| **pdu_append integration** | **Translated** — State events now call `append_state_pdu` |

## Implementation details

1. **database.hpp/database.cpp**: Added three new sled trees:
   - `stateid_pduid` — StateHash + (EventType, StateKey) → pdu_id (state at event)
   - `pduid_statehash` — PDU id → StateHash (state hash at each event)
   - `roomid_statehash` — room_id → latest StateHash

2. **data.hpp/data.cpp**: Added state resolution methods:
   - `append_state_pdu(room_id, pdu_id, state_key, event_type)` — generates new StateHash, stores state in `stateid_pduid`, links pdu to hash
   - `new_state_hash_id(room_id)` — computes hash from current state using `current_state_pduids`
   - `current_state_pduids(room_id)` — returns all `(type,key) -> pdu_id` pairs for current state
   - `get_statemap_by_hash(state_hash)` — builds full state map at an event
   - `prev_state_hash(current)` — walks back through state hash chain
   - `pdu_statehash(pdu_id)` — gets the StateHash for a specific PDU

3. **pdu_append integration**: State events now call `append_state_pdu` to update state resolution trees

4. **state_res.hpp/cpp**: Existing MSC4297 implementation provides `new_state_hash` for SHA-256 hashing

**Status:** Real implementation (core state resolution infrastructure for federation joins/room upgrades)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```