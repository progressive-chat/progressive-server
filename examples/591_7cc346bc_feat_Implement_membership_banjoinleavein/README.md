# Step 591: 7cc346bc - feat: Implement membership ban/join/leave/invite reason support

**Conduit commit:** `7cc346bc`
**Category:** Membership feature

## Summary

feat: Implement membership ban/join/leave/invite reason support

## C++ Translation

This commit adds `reason` parameter to membership events (join, leave, invite, kick, ban, unban).

### Changes:
1. **data.hpp/data.cpp**: Added `reason` parameter to:
   - `room_join(room_id, user_id, reason)`
   - `room_leave(room_id, user_id, reason)`
   - `room_invite(sender, room_id, user_id, reason)`
   - Added `room_kick(sender, room_id, user_id, reason)`
   - Added `room_ban(sender, room_id, user_id, reason)`
   - Added `room_unban(sender, room_id, user_id, reason)`
   - Membership events now include `reason` in content when provided

2. **ruma_wrapper.hpp**: Added `reason` field to `InviteRequest`

3. **main.cpp**: Updated route handlers:
   - `invite_user_route`: passes `body.reason` to `room_invite`
   - `leave` route: parses `reason` from request body

**Status:** Real implementation (not a placeholder).

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```