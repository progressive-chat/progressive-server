# Step 667 — "feat: space hierarchies" (Conduit `9d49d59`)

Source: [`timokoesters/conduit@9d49d59`](https://github.com/timokoesters/conduit/commit/9d49d59) (2023-07)

## What changed vs step 666

| Rust change | C++ translation |
|---|---|
| Feat: space hierarchies. Space (room hierarchy) support. 11 files changed. MAJOR feature. | **Translated** — Added MSC2946 space hierarchies with GET /rooms/{roomId}/hierarchy endpoint. |

## Implementation details

- **database.hpp/database.cpp**: Added space hierarchy trees:
  - `roomid_space_children` (parent_room_id -> child_room_ids)
  - `roomid_space_parents` (child_room_id -> parent_room_ids)
  - `roomid_space_chunk` (room_id -> cached hierarchy chunk)

- **data.hpp/data.cpp**: Added space hierarchy methods:
  - `space_children(room_id)` - get child rooms of a space
  - `space_parents(room_id)` - get parent spaces of a room
  - `space_add_child(parent, child)` / `space_remove_child(parent, child)` - manage relationships
  - `space_chunk_get(room_id)` / `space_chunk_set(room_id, json)` - cache hierarchy chunks

- **main.cpp**: Added `GET /_matrix/client/r0/rooms/{roomId}/hierarchy` endpoint:
  - Supports query parameters: `limit`, `skip`, `max_depth`, `suggested_only`
  - DFS traversal with depth limit
  - Returns room chunks with name, canonical_alias, topic, avatar, join_rule, num_joined_members
  - Caches chunks to avoid recomputation
  - Uses history visibility checks (`user_can_see_state_events`)

- Supports basic MSC2946 space hierarchy traversal (simplified - no nested children in chunks, no federation fallback)

**Status:** Real implementation (simplified).

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```