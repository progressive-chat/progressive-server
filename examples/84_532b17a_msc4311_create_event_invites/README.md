# Step 84 — "feat: MSC4311, Ensuring the create event is available on invites and knocks" (Conduit `532b17a`)

Source: [`timokoesters/conduit@532b17a`](https://github.com/timokoesters/conduit/commit/532b17a)

This step implements **MSC4311**: The `m.room.create` event is now included in the `stripped_state` of invite and knock sync entries, ensuring clients have access to the room's create event when receiving invites or knocks.

## What changed vs step 83

| Rust change | C++ translation |
|---|---|
| `utils::convert_stripped_state` includes create event as `RawStrippedState::Pdu` | `Data::room_create_event()` returns full create event PDU |
| Create event added to invite `stripped_state` | `sync_route` adds create event to `invited.stripped_state` |
| Create event added to knock `stripped_state` | `sync_route` adds create event to `knocked.stripped_state` |

## Implementation details

- Added `Data::room_create_event(room_id)` method to fetch the full `m.room.create` event PDU
- Modified `sync_route` to prepend the create event to `invited.stripped_state` and `knocked.stripped_state`
- The create event is included as a full PDU (matching `RawStrippedState::Pdu` in Conduit)

## Smoke test

```
POST /_matrix/client/r0/createRoom {}   -> 200 OK
GET /_matrix/client/r0/sync             -> create event in timeline
# Invite/knock sync now includes create event in stripped_state
```

Note: Invite endpoint has a pre-existing 404 issue unrelated to this change.