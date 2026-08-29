# Step 76 — "feat(media): retention policies" (Conduit `c3fb1b0`)

Source: [`timokoesters/conduit@c3fb1b0`](https://github.com/timokoesters/conduit/commit/c3fb1b0)

This step adds **media retention policies**: media can be automatically deleted when it
exceeds an age (`created`/`accessed`) or when the media store exceeds a `space` limit
(evicting the least-recently-accessed media). Conduit reads these from a config file
(`[[global.media.retention]]` with `humantime`/`bytesize` values); we read a JSON array
from `CONDUIT_MEDIA_RETENTION` (milliseconds/bytes).

## What changed vs step 75

| Rust change | C++ translation |
|---|---|
| `RetentionPolicy` config (scopes `local`/`remote`/`thumbnail` + `accessed`/`created`/`space`) | `database::RetentionPolicy {scope?, accessed_ms?, created_ms?, space_bytes?}` parsed in `Data` ctor from `CONDUIT_MEDIA_RETENTION` |
| `update_last_accessed`/`update_last_accessed_filehash` | `Media::update_last_access` sets `last_access` in the meta json; `Media::get` refreshes it on every download |
| `cleanup_time_retention` | `Media::cleanup_time_retention` deletes media whose `created`/`accessed` age exceeds the applicable policy |
| `files_to_delete` + `clear_required_space` (evict LRU until space fits) | `Media::clear_required_space` called before each upload; evicts least-recently-accessed media |
| periodic cleanup (1/10th shortest timeout, clamped 60s–24h) | detached `std::thread` in `main` calling `media_cleanup_time_retention` at `media_cleanup_interval_ms`; plus `POST /_conduit/admin/purge_time_retention` for an immediate run |

## Smoke test

```
CONDUIT_MEDIA_RETENTION='[{"created_ms":2000}]'
upload A; wait 3s; POST /_conduit/admin/purge_time_retention -> {"media_purged":1}; download A -> 404

CONDUIT_MEDIA_RETENTION='[{"space_bytes":12}]'
upload A,B (5 B each); upload C (5 B) -> A evicted (LRU); A 404, B 200, C 200
```
