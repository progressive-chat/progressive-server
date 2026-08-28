# Step 61 — "fix(membership): always set reason & allow new events if reason changed" (Conduit `d8badaf64bd2`, 2024-05-05)

Source: [`timokoesters/conduit@d8badaf64bd2`](https://github.com/timokoesters/conduit/commit/d8badaf64bd2)

## What changed vs step 60

| Rust change | C++ translation |
|---|---|
| `kick_user_route` / `ban_user_route` / `unban_user_route` gain reason-aware re-emission | `Data::room_kick` / `room_ban` / `room_unban` (new). When the target is already in the desired membership state with an unchanged `reason`, no new event is emitted (idempotent). Ban preserves `displayname` / `avatar_url` / `blurhash` from the prior member content. |
| `invite_helper` moves the "sender must be joined" permission check into the local (non-federation) branch | `invite_user_route` now returns `M_FORBIDDEN` if the sender is not joined to the room |

| Rust change | C++ translation |
|---|---|
| `GET /rooms/<id>/event/<event_id>` — joined membership required, returns the raw stored PDU; missing → M_NOT_FOUND "Event not found." | identical, via existing `Data::pdu_get` (eventid_pduid → pduid_pdus lookup from step 6) |

## Verified

```
joined user GET event   → 200 full signed PDU JSON
non-member GET event    → 403 You don't have permission
nonexistent event       → 404 M_NOT_FOUND
```
