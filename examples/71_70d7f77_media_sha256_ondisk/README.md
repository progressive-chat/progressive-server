# Step 71 — "feat(media): use file's sha256 for on-disk name & make directory configurable" (Conduit `70d7f77`)

Source: [`timokoesters/conduit@70d7f77`](https://github.com/timokoesters/conduit/commit/70d7f77)

This step changes how media is stored. Conduit now keys the **file bytes** by the
**sha256 of their content** (so identical uploads are deduplicated) and keeps the
metadata (`filename`, `content_type`, `created_at`, `file_size`, `sha256`) in a separate
tree keyed by `(server_name, media_id)`. The public `Media` API changes from
`create(mxc, …)` / `get(mxc)` to `create(server_name, media_id, …)` / `get(server_name, media_id)`.

## What changed vs step 70

| Rust change | C++ translation |
|---|---|
| media bytes stored under `sha256(content)` | `mediaid_file` tree now keyed by `sha256_hex(content)` (dedup) |
| new `mediaid_meta` tree | `mediaid_meta` tree: `server + 0xff + media_id` -> json metadata |
| `Media::create(server, id, filename, ct, file)` | `Media::create(server_name, media_id, filename, content_type, file)` computes the digest, inserts bytes (dedup), writes metadata |
| `Media::get(server, id)` | `Media::get(server_name, media_id)` reads metadata, then loads bytes by digest |
| configurable on-disk directory | no-op: we keep media in the DB (RocksDB), not on a filesystem, so there is no configurable directory to honor |

## Smoke test

```
POST /_matrix/media/r0/upload?filename=hello.txt  -> {"content_uri":"mxc://localhost/<id>"}
GET  /_matrix/media/r0/download/localhost/<id>     -> 200, Content-Type text/plain, body "hello-media-content"
GET  /_matrix/client/v1/media/download/localhost/<id>/hello.txt -> 200, inline disposition
```
