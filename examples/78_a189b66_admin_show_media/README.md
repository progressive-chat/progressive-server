# Step 78 — "feat(admin): show media command" (Conduit `a189b66`)

Source: [`timokoesters/conduit@a189b66`](https://github.com/timokoesters/conduit/commit/a189b66)

This step adds an admin **show media** command: an admin provides an MXC URI and the server
fetches the media so the admin can view it. In Conduit the `!show-media <mxc>` command sends
the media into the admin room as a message; we expose the equivalent as an admin HTTP
endpoint that returns the media bytes with its stored Content-Type (gated by admin auth).

## What changed vs step 77

| Rust change | C++ translation |
|---|---|
| `AdminCommand::ShowMedia` sends the media as a message in the admin room | `POST /_conduit/admin/show_media` `{server_name?, media_id}` → 200 with media bytes + Content-Type + inline Content-Disposition (404 `M_NOT_FOUND` if it does not exist) |
| `get_content`/`media` modules made `pub` (visibility only) | n/a |

## Smoke test

```
POST /_conduit/admin/show_media {media_id: A}   -> 200, body "viewable-bytes", Content-Type image/png
POST /_conduit/admin/show_media {media_id: "missing"} -> 404
```
