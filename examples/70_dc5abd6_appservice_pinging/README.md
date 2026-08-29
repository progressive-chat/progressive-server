# Step 67 — "feat(client-server): add knocking" (Conduit `21af83e`)

Source: [`timokoesters/conduit@21af83e`](https://github.com/timokoesters/conduit/commit/21af83e)

This step implements the **client-server knocking feature** introduced by `21af83e`.
Upstream's commit is a large refactor (state-cache helpers, a new `service/rooms/helpers`
module, syncing the knock state to clients). Our simpler membership framework already
supports the behaviour, so we translate the *feature* rather than the *refactor*: a knock
is an `m.room.member` state event with `membership: "knock"` that an admin resolves by
inviting the user (then the user joins).

## What changed vs step 66

| Rust change | C++ translation |
|---|---|
| `POST /_matrix/client/r0/rooms/{roomId}/knock` | New route `rooms/(.+)/knock`: requires an access token, parses an optional `reason`, checks the room exists, the user is not already joined/invited, and that the room's `m.room.join_rules` `join_rule` is `"knock"` (public rooms must be joined, not knocked) |
| Knock leaves an `m.room.member` event (`membership: "knock"`) | `Data::room_knock(room_id, user_id, reason)` appends that state event without adding the user to the joined set |

## Resolving a knock

An admin (who is joined to the room) invites the knocked user via the existing
`POST /rooms/{id}/invite` route (body `{"recipient":{"user_id":"@bob:localhost"}}`);
the invite `m.room.member` event supersedes the knock state event for that
`state_key`. The knocked user then joins through the existing `POST /join/{id}`
route. Verified end-to-end: a knock (`membership:"knock"`) is replaced by an
invite (`membership:"invite"`) once the admin invites.

## Known limitation

Knocked rooms are not yet surfaced in `/sync`; the knock is recorded as room state
and is observable via `/rooms/{id}/members` or `/rooms/{id}/state`. Sync surfacing
is a follow-up.

## Verified

```
POST /knock (no token)            → 401 M_UNKNOWN_TOKEN
POST /knock (unknown room)        → 404 M_NOT_FOUND
POST /knock on public room        → 403 "You cannot knock on a public room."
POST /knock on knockable room     → 200 {} ; member event membership="knock" (+reason) stored
POST /knock again (re-knock)      → 200 {} ; reason updated in place
POST /rooms/{id}/invite (admin)   → 200 {} ; knock state replaced by invite
```
