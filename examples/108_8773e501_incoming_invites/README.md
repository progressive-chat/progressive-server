# Step 108 — "feat: incoming invites over federation" (Conduit `8773e501`)

Source: [`timokoesters/conduit@8773e501`](https://github.com/timokoesters/conduit/commit/8773e501) (2021-04-11)

## What changed vs step 107

| Rust change | C++ translation |
|---|---|
| **Invite state + count trees** (`userroomid_invited` → `userroomid_invitestate`, `roomuserid_invited` → `roomuserid_invitecount`) | **Implemented** — `userroomid_invitestate` (user+room → invite_state JSON), `roomuserid_invitecount` (room+user → BE u64) alongside legacy `userid_inviteroomids` |
| **`rooms_invited` returns `(room, invite_state)` + `get_invite_count`** | **Implemented** — `rooms_invited_with_state()`, `get_invite_count()`, `build_invite_state()` (stripped join_rules/canonical_alias/avatar/name), `store_invite()` |
| **`update_membership` takes `invite_state`** | **Implemented** — `update_membership(..., optional<json> invite_state)`; invite stores state + bumps count, join/leave clear both |
| **Sync serves stored invite_state, skips `since >= invite_count`** | **Implemented** — sync invited block uses `rooms_invited_with_state` + count filter, falls back to full state |
| **Local `/rooms/:id/invite` always 404 (sender never copied from token)** | **Fixed** — copy `wrapper.user_id` into `InviteRequest::user_id`
| **New federation `PUT /_matrix/federation/v[12]/invite/:roomId/:eventId`** | **Implemented** — validates membership/sender/state_key/local user, rejects room_version < 6, signs via `hash_and_sign_event`, stores, returns `{event}` |
| **ruma/state-res version bumps, `state_get` → `state_get_id` split** | **Documented** — No ruma in C++; canonical-JSON plumbing already untyped (`nlohmann::json`), no change needed |
| **sled stable revert / `flush_async` noop** | **Documented** — RocksDB adapter has no `flush_async`; no change needed |

## Implementation details

1. **Database** — `database.hpp/.cpp`: two new trees + constructor/open wiring.
2. **Data** — `data.hpp/.cpp`: invite-state API + `handle_incoming_invite()` (local-user check, sign, persist PDU + state).
3. **Sync** — `main.cpp` `sync_route`: stored invite_state with count filter.
4. **Federation** — `main.cpp`: shared `invite_handler` for v1+v2 invite routes.

## Known pre-existing issue (not from this commit)

All locally-signed events currently carry empty signatures (`"ed25519:": ""`):
`utils::generate_keypair()` returns a 43-byte versioned blob while
`crypto::Ed25519Key` only accepts 32-byte raw seeds, so `hash_and_sign_event`
silently emits empty sigs. This predates step 108 (same on step 107 timelines)
and is left untouched here — the signing-key fix belongs to its own step.
The federation invite path signs exactly like `pdu_append`, so behavior is
consistent.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server
```
