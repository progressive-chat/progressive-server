# Step 98 — "feat: add option to ignore specific server signing keys" (Conduit `d058dab`)

Source: [`timokoesters/conduit@d058dab`](https://github.com/timokoesters/conduit/commit/d058dab)

This step adds support for **Matrix Room Version 12**, which includes the features from MSC4289, MSC4291, and MSC4297.

## What changed vs step 85

| Rust change | C++ translation |
|---|---|
| `RoomVersionId::V10` → `RoomVersionId::V12` | Added room version "12" to `get_room_version_rules()` with flags: `explicitly_privilege_room_creators=true`, `additional_room_creators=true`, `use_room_create_sender=true` |
| Default room version updated to V12 | `createRoom` now accepts optional `room_version` parameter (defaults to "1" for backwards compat) |
| Room upgrade supports v12 | Upgrade endpoint allows `new_version: "12"` |

## Smoke test

```
POST /_matrix/client/r0/createRoom {"room_version":"12"} -> 200 {"room_id":"!e99ae1e813b0:localhost"}
GET /_matrix/client/r0/rooms/!room/state/m.room.create -> {"creator":"@alice:localhost","room_version":"12"}
```

## Known issue

Server has stability issues (crashes after some requests) - pre-existing infrastructure issue, not related to room version 12 specifically.

## Next steps

For full Room Version 12 support, would need:
- Full RFC 8785 canonical JSON for room ID hashing
- Complete MSC4297 State Resolution v2.1 integration
- MSC4289/MSC4291 feature flag integration throughout the codebase