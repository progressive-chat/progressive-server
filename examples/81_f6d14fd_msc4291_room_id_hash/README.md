# Step 81 — "feat: MSC4291, Room IDs as hashes of the create event (1/2)" (Conduit `f6d14fd`)

Source: [`timokoesters/conduit@f6d14fd`](https://github.com/timokoesters/conduit/commit/f6d14fd)

This step implements **MSC4291 part 1**: Room IDs are now derived from a hash of the `m.room.create` event content, rather than random strings. This is the first half of MSC4291 (the second half `bd8686e` updates references).

## What changed vs step 80

| Rust change | C++ translation |
|---|---|
| `RoomId::new_v1()` | Room ID computed as `!` + first 12 hex chars of SHA256(canonical create event content) + `:hostname` |
| Canonical JSON for hashing | Simplified deterministic JSON (sorted keys, compact) for SHA256 |
| `RoomId::new_v1()` in upgrades | Applied to room replacement logic |

## Smoke test

```
POST /_matrix/client/r0/createRoom {}   -> {"room_id":"!378311bd97b0:localhost"} (12-char hash)
GET /_matrix/client/r0/rooms/!room/state/m.room.create
  -> {"creator":"@alice:localhost","room_version":"1"}
POST /_matrix/client/r0/createRoom {additional_creators:["@bob:localhost"]}
  -> m.room.create has {"additional_creators":["@bob:localhost"],"creator":"@alice:localhost","room_version":"1"}
GET /_matrix/client/r0/rooms/!room/state/m.room.power_levels
  -> {"users":{"@alice:localhost":100,"@bob:localhost":100},...}
```

Note: The canonical JSON implementation is simplified (deterministic JSON with sorted keys). Full RFC 8785 canonical JSON can be added later.