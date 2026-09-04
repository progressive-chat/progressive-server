# Step 790 — msc4291_room_id_hash_2

Source: [`timokoesters/conduit@bd8686e`](https://github.com/timokoesters/conduit/commit/bd8686e) (2025-08-11)

## What changed vs step 789

| Rust change | C++ translation |
|---|---|
| Updates `createRoom` to use the hash-based room ID from MSC4291 when the room version supports it. | **Requires major infrastructure** — Room IDs derived from create event hash (MSC4291). 20 files changed. |

## Implementation details

This commit implements MSC4291 - Room IDs as hashes of the create event:

1. **Room ID generation**: Room IDs are now derived from the hash of the create event content
2. **Room version support**: Only for room versions that support MSC4291 (v11+)
3. **Create event validation**: The create event must be valid and its hash becomes the room ID
4. **State resolution**: Updated to work with hash-based room IDs
5. **Federation**: Updated to handle hash-based room IDs

**Status:** Major infrastructure change requiring:
- New room ID generation logic
- Updated state resolution
- Federation updates
- Timeline changes

This is a fundamental change to how room IDs work and would require significant refactoring.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```