# Step 75 — "feat(media): blocking" (Conduit `594fe5f`)

Source: [`timokoesters/conduit@594fe5f`](https://github.com/timokoesters/conduit/commit/594fe5f)

This step adds **media blocking**: admins can block individual media (by MXC server + id),
block every media uploaded by a user, list blocked media, and unblock them. Blocked media
looks like it does not exist: every download/thumbnail endpoint (r0, client v1, federation)
returns `404 M_NOT_FOUND`. Blocking also works at the **content-hash** level: media uploaded
after its content hashtag was blocked is silently not stored (and 404s when fetched).

## What changed vs step 74

| Rust change | C++ translation |
|---|---|
| new trees `blocked_servername_mediaid`, `blocked_filehash` | `Media` gains a 3rd/4th tree: `server+0xff+media_id -> 8-byte secs + reason` and `sha256_hex -> 8-byte secs + reason` |
| `Media::check_blocked` / `is_blocked` called in all content routes | `download_handler` + v1 client route call `media_is_blocked` before serving → 404 |
| `is_blocked` (directly or via sha256) | `Media::is_blocked`: direct lookup OR meta's `sha256` in `blocked_hash_` |
| `create_file_metadata` skips file when `is_blocked_filehash` | `Media::create` skips `tree_.insert` when the content hash is blocked (metadata still recorded) |
| `block` / `block_from_user` / `unblock` / `list_blocked` | `Media::block` / `block_by_user` (with `after_secs` filter) / `unblock` (drops hash block when last reference) / `list_blocked` |
| admin commands `!block-media`, `!block-media-from-users`, `!list-blocked-media`, `!unblock-media` | HTTP endpoints: `POST /_conduit/admin/block_media`, `POST /_conduit/admin/block_media_from_users`, `GET /_conduit/admin/list_blocked_media`, `POST /_conduit/admin/unblock_media` |

## Smoke test

```
upload A,B as @alice:localhost (download 200)
POST /_conduit/admin/block_media {media_id: A, reason:"spam"}  -> {"blocked":true,"purged":0}
GET  /_matrix/media/r0/download/localhost/A                   -> 404
GET  /_conduit/admin/list_blocked_media                       -> A with reason + sha256_hex
POST /_conduit/admin/unblock_media {media_id: A}              -> {"unblocked":true}; download 200
POST /_conduit/admin/block_media_from_users {user_ids:["@alice:localhost"]} -> {"blocked":2}
bob uploads identical content to blocked B  -> 404 (blocked via content hash)
```
