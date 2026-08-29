# Step 74 — "feat(admin): commands for purging media" (Conduit `d766370`)

Source: [`timokoesters/conduit@d766370`](https://github.com/timokoesters/conduit/commit/d766370)

This step adds admin commands to **purge media**: by id, by uploading user, by server, and
(as a flag) while deactivating a user. Conduit's commands are room-based (`!purge-media-by-id`,
`!purge-media-from-users`, `!purge-media-from-server`, plus `--purge-media` on deactivate).
We expose them as admin HTTP endpoints (consistent with our existing `/_conduit/admin/*` API).

## What changed vs step 73

| Rust change | C++ translation |
|---|---|
| `Media::purge_and_get_hashes` / `purge_from_user` / `purge_from_server` | `Media::remove` / `remove_by_user` / `remove_by_server` (refcounted: bytes dropped only when no other meta references the sha256, or when `force_filehash` is set) |
| `DbFileMeta::user_id` (from 3171b77) drives per-user purge | `remove_by_user` matches the `user_id` field in `mediaid_meta` |
| `after` timestamp filter ("purge media uploaded in the last {timeframe}") | `after_ms` (unix-ms) parameter; only entries with `created_at >= after_ms` are removed |
| `force_filehash` deletes shared bytes | `force` parameter passed through to `remove` |
| room commands | HTTP: `POST /_conduit/admin/purge_media` `{media_id, server_name?, force_filehash?}`, `POST /_conduit/admin/purge_media_from_users` `{user_ids[], after_ms?, force_filehash?}`, `POST /_conduit/admin/purge_media_from_server` `{server_name, after_ms?, force_filehash?}` (refuses our own server, mirroring Conduit) |
| `--purge-media` on deactivate | `POST /_conduit/admin/user/{userId}/deactivate` now accepts `purge_media`, `after_ms`, `force_filehash` |

## Smoke test

```
register @alice:localhost (admin), upload 3 media as alice
POST /_conduit/admin/purge_media {media_id: SID1}        -> {"purged":1,"failed":0}
GET  /_matrix/media/r0/download/localhost/SID1           -> 404
POST /_conduit/admin/purge_media_from_users {user_ids:["@alice:localhost"]} -> {"media_purged":2}
POST /_conduit/admin/purge_media_from_server {server_name:"localhost"}      -> 400 (own server)
POST /_conduit/admin/user/@bob:localhost/deactivate {purge_media:true}      -> {"deactivated":true,"media_purged":1}
```

(Note: `19d0ea4` "deep hashed directory structure" was intentionally skipped — it only
reorganizes the on-disk file layout; our media already lives in a single RocksDB tree keyed
by sha256, so there is no corresponding C++ change.)
