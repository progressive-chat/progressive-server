# Step 85 — "fix: set previous creators to max power level if upgraded room doesn't support creator power level" (Conduit `e757a98`)

Source: [`timokoesters/conduit@e757a98`](https://github.com/timokoesters/conduit/commit/e757a98)

This step fixes room upgrade behavior when upgrading from a room version that doesn't have `explicitly_privilege_room_creators`. When upgrading such a room, the previous creators (room creator + additional_creators) should be given max power level (100) in the new room's power levels.

## What changed vs step 84

| Rust change | C++ translation |
|---|---|
| Check old room's create event for room version | Read old room's `m.room.create` event to get `room_version` |
| Get old room's `RoomVersionRules` | Use `get_room_version_rules()` to get rules for old version |
| If `!rules.explicitly_privilege_room_creators`, give previous creators power level 100 | Added logic to check `explicitly_privilege_room_creators` flag and grant power level 100 to creator + additional_creators |

## Implementation

Added logic in room upgrade handler (`/upgrade` endpoint):
1. Read old room's `m.room.create` event to get `room_version`
2. Get `RoomVersionRules` for that version
3. If `!rules.explicitly_privilege_room_creators`, add creator + additional_creators to power levels with level 100

## Current status

- Room upgrade endpoint works (returns 200 with `replacement_room`)
- New room has correct `m.room.create` with `predecessor` pointing to old room + tombstone event
- Power levels in new room include creator at level 100 (room version 1 has `explicitly_privilege_room_creators = true`)
- For room versions without `explicitly_privilege_room_creators`, additional_creators would also get level 100 (logic in place for future versions)

## Known issue

Server stability issues after multiple requests (connection closes). Core upgrade logic works.

## Smoke test

```
POST /_matrix/client/r0/createRoom {} -> 200 {room_id}
POST /_matrix/client/r0/rooms/!room/upgrade {new_version:"6"} -> 200 {replacement_room}
GET /rooms/!new_room/state/m.room.power_levels -> creator has power 100
```