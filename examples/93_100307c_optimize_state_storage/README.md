# Step 93 — "improvement: optimize state storage" (Conduit `100307c`)

Source: [`timokoesters/conduit@100307c`](https://github.com/timokoesters/conduit/commit/100307c) (2021-03-17)

## What changed vs step 92

| Rust change | C++ translation |
|---|---|
| **Optimize state storage** | **Requires major refactor** — Short ID system for state |
| **Major rooms.rs refactor** | **Requires major refactor** — Short ID system |
| **Sync improvements** | **Partial** — Some optimizations possible |

## Implementation details

This is a **major database schema refactor** that introduces a short ID system:

1. **Short ID system** for:
   - State hashes → short integer IDs (`statehash_shortstatehash`)
   - Event IDs → short IDs (`eventid_shorteventid`, `shorteventid_eventid`)
   - State keys → short state keys (`statekey_shortstatekey`)
   - State hashes → short state hashes (`statehash_shortstatehash`)

2. **New database trees**:
   - `roomid_shortstatehash` — room_id → short state hash
   - `statehash_shortstatehash` — state hash → short state hash
   - `statekey_shortstatekey` — (event_type, state_key) → short state key
   - `stateid_shorteventid` — short state hash + short state key → short event ID
   - `shorteventid_eventid` — short event ID → event ID
   - `eventid_shorteventid` — event ID → short event ID
   - `stateid_shorteventid` — short state hash + short state key → short event ID
   - `statehash_shortstatehash` — state hash → short state hash
   - `roomid_shortstatehash` — room ID → short state hash

3. **Changes to state resolution**:
   - `state_full` now takes `shortstatehash` instead of `state_hash`
   - `state_get` uses `shortstatehash` and `shortstatekey`
   - `append_to_state` uses short IDs
   - `set_room_state` uses `shortstatehash` (u64) instead of string hash

4. **Sync improvements** in sync.rs

**Status:** Major refactor required — our C++ implementation would need:
- New database trees for short ID mappings
- Complete rewrite of state resolution logic
- Changes to pdu_append, state resolution, sync
- Counter-based short ID generation

This is a **major infrastructure change** that would require significant refactoring.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```