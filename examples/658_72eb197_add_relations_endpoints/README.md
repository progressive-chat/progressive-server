# Step 658 — "Add relations endpoints, edits and threads work now" (Conduit `72eb197`)

Source: [`timokoesters/conduit@72eb197`](https://github.com/timokoesters/conduit/commit/72eb197) (2023-06)

## What changed vs step 657

| Rust change | C++ translation |
|---|---|
| Add relations endpoints, edits and threads work now. Relations API (MSC3440) implementation. 8 files changed. MAJOR feature. | **Translated** — Added MSC3440 relations endpoints (edits, threads, reactions). |

## Implementation details

- **database.hpp/database.cpp**: Added `eventid_relations` MultiValue tree to store relations.
  - Key format: `'r' + event_id + 0xff + rel_type + 0xff + event_type` → related_event_id
  - Updated `Database` constructor and `open()` method.

- **data.hpp/data.cpp**: Added methods:
  - `add_relation(event_id, rel_type, event_type, related_event_id)` - stores a relation
  - `get_relations(event_id, rel_type, event_type)` - retrieves relations with optional filters
  - Integrated into `pdu_append()` to automatically extract `m.relates_to` from events

- **main.cpp**: Added three relations endpoints (MSC3440):
  1. `GET /_matrix/client/r0/rooms/{roomId}/relations/{eventId}` - all relations
  2. `GET /_matrix/client/r0/rooms/{roomId}/relations/{eventId}/{relType}` - filter by rel_type
  3. `GET /_matrix/client/r0/rooms/{roomId}/relations/{eventId}/{relType}/{eventType}` - filter by rel_type and event_type

- Supports common relation types: `m.annotation` (edits), `m.thread` (threads), `m.reaction` (reactions), `m.reference` (references)

**Status:** Real implementation (simplified - no pagination, basic filtering).

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```