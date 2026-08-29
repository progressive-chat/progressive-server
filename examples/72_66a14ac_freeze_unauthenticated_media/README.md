# Step 72 — "feat: freeze unauthenticated media" (Conduit `66a14ac`)

Source: [`timokoesters/conduit@66a14ac`](https://github.com/timokoesters/conduit/commit/66a14ac)

This step adds the ability to **freeze unauthenticated media access**. Conduit had a
per-media `unauthenticated_access_permitted` flag that was previously ignored; it is now
honored. When a media item is uploaded while
`media.unauthenticated_access_permitted` (our `CONDUIT_MEDIA_UNAUTHENTICATED_ACCESS_PERMITTED`,
default `true`) is `false`, that media can only be fetched through an **authenticated**
media endpoint — the unauthenticated `r0` routes return `404` for it. Existing media keeps
the permission it was uploaded with ("frozen").

## What changed vs step 71

| Rust change | C++ translation |
|---|---|
| `Media::get(server, media_id, authenticated)` | `Media::get(server_name, media_id, authenticated)`; returns `nullopt` when `!authenticated && !unauthenticated_access_permitted` |
| `DbFileMeta::unauthenticated_access_permitted` stored at upload | `Media::create(..., unauthenticated_access_permitted)` writes the flag into the `mediaid_meta` json |
| client `r0` media routes pass `authenticated=false`; auth/v1/federation pass `true` | `download_handler` gains an `authenticated` param; `r0/download` & `r0/thumbnail` → `false`, v1 client & federation → `true` |
| config `media.unauthenticated_access_permitted` (default `true`) | `Data::media_unauthenticated_access_permitted_` read from `CONDUIT_MEDIA_UNAUTHENTICATED_ACCESS_PERMITTED` (default `true`); used at upload time |

## Smoke test

```
# freeze on:
CONDUIT_MEDIA_UNAUTHENTICATED_ACCESS_PERMITTED=false
POST /_matrix/media/r0/upload?filename=f.txt          -> mxc://localhost/<id>
GET  /_matrix/media/r0/download/localhost/<id>        -> 404  (frozen)
GET  /_matrix/client/v1/media/download/localhost/<id>/f.txt (token) -> 200 "frozen-content"

# default (unfrozen):
GET  /_matrix/media/r0/download/localhost/<id>        -> 200
```
