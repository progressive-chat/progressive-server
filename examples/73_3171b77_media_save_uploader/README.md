# Step 73 — "feat(media): save user id of uploader" (Conduit `3171b77`)

Source: [`timokoesters/conduit@3171b77`](https://github.com/timokoesters/conduit/commit/3171b77)

This step records **who uploaded each media item**. Conduit adds a `user_id` field to
`DbFileMeta` and two index trees (`servername_userlocalpart_mediaid`,
`servernamemediaid_userlocalpart`) so media can later be enumerated/purged per user.

## What changed vs step 72

| Rust change | C++ translation |
|---|---|
| `Media::create(..., user_id)` | `Media::create(..., user_id: optional<string>)`; stores `"user_id"` in the `mediaid_meta` json (null for remote/federated media) |
| `create_file_metadata` gets `user_id` | `Data::media_create` gains `user_id`; the upload route resolves the authenticated sender via `user_from_token` and passes it |
| two new index trees for purge-by-user | not needed: `mediaid_meta` already carries `user_id`, so "media by user" can be answered by scanning the meta tree (used in the next step's purge commands) |

## Smoke test

Upload as `@alice:localhost`; the meta record now carries `"user_id": "@alice:localhost"`.
(Verified indirectly by the purge-by-user admin command added in the next step.)
