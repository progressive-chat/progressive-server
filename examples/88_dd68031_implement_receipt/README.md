# Step 88 — "improvement: implement /receipt" (Conduit `dd68031`)

Source: [`timokoesters/conduit@dd68031`](https://github.com/timokoesters/conduit/commit/dd68031) (2021-03-02)

## What changed vs step 87

| Rust change | C++ translation |
|---|---|
| **Implement /receipt** | **Translated** — Added POST /rooms/{room_id}/receipt/m.read/{event_id} endpoint |
| **Major read_marker refactor** | **Translated** — Added private_read_set and readreceipt_update methods |

## Implementation details

1. **Added EDU database trees** in database.hpp/cpp:
   - `userid_receipt` — user+0xff+room+0xff+event_id -> receipt JSON
   - `roomid_receipt` — room+0xff+user -> receipt JSON

2. **Added receipt methods in data.hpp/cpp**:
   - `private_read_set(room_id, user_id, pdu_count)` — sets private read marker
   - `readreceipt_update(user_id, room_id, event_id, timestamp)` — updates read receipt with timestamp

3. **Added receipt endpoint in main.cpp**:
   - `POST /_matrix/client/r0/rooms/{room_id}/receipt/m.read/{event_id}`
   - Validates user is in room
   - Gets PDU count for event
   - Calls private_read_set and readreceipt_update

**Status:** Real implementation

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```