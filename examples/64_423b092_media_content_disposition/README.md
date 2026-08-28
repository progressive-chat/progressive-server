# Step 64 — "use ruma content disposition type in place of string" (Conduit `423b092`, 2024-07-15)

Source: [`timokoesters/conduit@423b092`](https://github.com/timokoesters/conduit/commit/423b092)

## What changed vs step 63

| Rust change | C++ translation |
|---|---|
| `ContentDisposition` (ruma `http_headers`) replaces hand-built `inline; filename=...` strings in `create_content_route`, `get_content_route`, `get_content_as_filename_route` | `inline_content_disposition(filename)` helper builds a properly RFC 6266-quoted/escaped `inline; filename="..."` header (drops control chars, escapes `"`/`\`). Used by both the download handler and the v1 `/filename` download route. |
| `get_content_as_filename_route` had a latent `inline: filename=` (colon) bug — the typed `ContentDisposition` fixes formatting | raw concatenation replaced by the escaping helper (correct `inline; filename=` form) |

We regenerate the disposition from the stored filename on download (Conduit persists it in the media DB); the observable header is identical.

## Verified

```
GET download of uploaded file  → 200, Content-Disposition: inline; filename="<name>"
GET v1 /filename download     → 200, same properly-formatted header
filename with quote/backslash → escaped in header
```
