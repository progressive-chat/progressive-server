# Step 66 — "fix(media): return an error when content is failed to be parsed as an image" (Conduit `30855ce`)

Source: [`timokoesters/conduit@30855ce`](https://github.com/timokoesters/conduit/commit/30855ce)

## What changed vs step 65

| Rust change | C++ translation |
|---|---|
| `get_content_thumbnail` and `Service::get_thumbnail`: when image parsing fails to generate a thumbnail, **return an error** instead of falling back to serving the original file | `download_handler` now, in thumbnail mode (`allow_filename == false`), returns `M_UNKNOWN` "Unable to generate thumbnail for the requested content (likely is not an image)" (HTTP 400) instead of serving the original bytes. The previous behaviour (serving the original as a "thumbnail") is exactly the upstream fallback this commit removes. |

This covers the r0, v1 and federation thumbnail routes, which all funnel through `download_handler` with `allow_filename == false`.

## Verified

```
GET /thumbnail/<server>/<id> (local media) → 400 M_UNKNOWN "Unable to generate thumbnail..."
GET /download/<server>/<id>                → 200, still serves file with inline disposition
GET /thumbnail/<server>/<id> (missing)     → 404 M_NOT_FOUND
```
