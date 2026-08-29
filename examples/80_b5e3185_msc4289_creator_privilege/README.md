# Step 80 — "feat: MSC4289, Explicitly privilege room creators (1/2)" (Conduit `b5e3185`)

Source: [`timokoesters/conduit@b5e3185`](https://github.com/timokoesters/conduit/commit/b5e3185)

This step implements **MSC4289 (part 1): Explicitly privilege room creators**. The key changes:

1. **Room creators get power level 100 by default** (unless room version has `explicitly_privilege_room_creators = false`)
2. **`additional_creators` field** in room creation - list of users who are also room creators
3. **TrustedPrivateChat preset**: invited users also get power level 100 (if room version has `additional_room_creators`)
4. **Room version rules** structure with flags:
   - `explicitly_privilege_room_creators` (default true)
   - `additional_room_creators` (default false)
   - `use_room_create_sender` (default false)

## What changed vs step 79

| Rust change | C++ translation |
|---|---|
| `RoomCreateEventContent::additional_creators` | `CreateRoomRequest::additional_creators` field in request |
| `RoomCreateEventContent` includes `room_version` and `additional_creators` | `m.room.create` event content now includes these fields |
| Creator gets power level 100 by default | Power levels event includes creator + additional_creators at level 100 |
| TrustedPrivateChat gives invited users power 100 | Handled if room version has `additional_room_creators` |
| Room version rules | `RoomVersionRules` struct with flags |

## Smoke test

```
# Create room with additional_creators
POST /_matrix/client/r0/createRoom {preset:"trusted_private_chat", invite:["@bob:localhost"], additional_creators:["@bob:localhost"]}
-> 200 {room_id: "!..."}

# Power levels show creator + additional_creators at level 100
GET /_matrix/client/r0/rooms/!room/state/m.room.power_levels
-> {"users":{"@alice:localhost":100,"@bob:localhost":100},...}

# m.room.create includes additional_creators + room_version
GET /_matrix/client/r0/rooms/!room/state/m.room.create
-> {"creator":"@alice:localhost","additional_creators":["@bob:localhost"],"room_version":"1"}
```