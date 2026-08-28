# Step 63 — "fix: permission checks for aliases" (Conduit `144d548`, 2024-06-11)

Source: [`timokoesters/conduit@144d548`](https://github.com/timokoesters/conduit/commit/144d548)

## What changed vs step 62

| Rust change | C++ translation |
|---|---|
| `create_alias_route` / `delete_alias_route` capture the authenticated `sender_user` and thread it into the data layer | `PUT`/`DELETE /_matrix/client/r0/directory/room/<alias>` now require a valid access token (401 `M_UNKNOWN_TOKEN` otherwise) and pass the resolved `sender_user` to `set_alias` / `remove_alias` |
| `Data::set_alias` gains a `user_id` and records the alias creator in a new `alias_userid` table | `Data::set_alias(alias, room_id, user_id)` now also writes `alias_creator` (new `sled::Tree`); `Data::remove_alias(alias, user_id)` also erases `alias_creator` |
| new `Data::who_created_alias` | `Data::who_created_alias(alias)` returns `optional<string>` creator user id |
| `globals` gains `admin_alias` (`#admins:<server_name>`) + getter | `Data` gains `admin_alias()` returning `#admins:<hostname>` (set in `set_hostname`) |

Skipped parts (CLI-only, not part of the HTTP server translation): the `conduit-admin`
`create-alias`/`delete-alias` command changes in `service/admin/mod.rs`.

## Verified

```
PUT  alias with no token        → 401 M_UNKNOWN_TOKEN
PUT  alias with token           → 200, alias creator recorded
GET  alias (resolve)            → 200 room_id
who_created_alias returns creator
DELETE alias with token         → 200, alias + creator removed
```
