# Step 77 — "feat(admin): list & query information about media" (Conduit `fd16e9c`)

Source: [`timokoesters/conduit@fd16e9c`](https://github.com/timokoesters/conduit/commit/fd16e9c)

This step adds two admin capabilities for inspecting the media store: **query** a single
media item (its metadata, uploader, content hash, block status, timestamps, size) and
**list** media with optional filters (server/user, content-type, creation window).

## What changed vs step 76

| Rust change | C++ translation |
|---|---|
| `MediaQuery` / `MediaQueryFileInfo` / `FileInfo` | `Media::media_query` returns `MediaQuery` (is_blocked + source_file info) |
| `MediaListItem` list + filters (server/user, content_type, before/after, thumbnails) | `Media::media_list` scans `mediaid_meta` applying server/user/content_type/before_ms/after_ms filters (thumbnails vacuous: none stored) |
| admin commands `!list-media`, `!query-media` | `POST /_conduit/admin/query_media` `{server_name?, media_id}` (404 when missing) and `POST /_conduit/admin/list_media` `{server_name?, user_id?, content_type?, before_ms?, after_ms?}` |

## Smoke test

```
POST /_conduit/admin/query_media {media_id: A} -> is_blocked, source_file{
  sha256_hex, filename, content_type, uploader, creation, last_access, size}
POST /_conduit/admin/list_media {}                -> all media
POST /_conduit/admin/list_media {content_type:"image/png"} -> matched; "text/plain" -> []
POST /_conduit/admin/query_media {media_id:"nope"} -> 404
```
