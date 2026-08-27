# Step 14 — "feat: media" (Conduit `821c608c`, 2020-05-18)

Source: [`timokoesters/conduit@821c608c`](https://github.com/timokoesters/conduit/commit/821c608c)
— the media repository: `mxc://` upload, download and thumbnails.

Folded prerequisite: `MESSAGE_LIMIT` raised to 20 MB upstream in this commit.

## What changed vs step 13

| Rust change | C++ translation |
|---|---|
| new `database/media.rs`: `Media { mediaid_file: Tree }`; key = MXC + 0xff + filename + 0xff + content_type; value = raw bytes | `database::Media` over a RocksDB column family (`src/media.hpp/cpp`) |
| `POST /_matrix/media/r0/upload?filename=…` — generates `mxc://<host>/<random 256>` | same; body IS the file, Content-Type preserved |
| `GET /_matrix/media/r0/download/<server>/<media_id>` — returns bytes + content type (+ filename) | identical |
| `GET /_matrix/media/r0/thumbnail/...` | served original (upstream did too at this point) |
| `GET /_matrix/media/r0/config` → `upload_size: 20 MB` | identical |

## Verified

```console
$ curl -H "$AUTH" -H "Content-Type: image/png" --data-binary @pic.png \
    ".../r0/upload?filename=pic.png"
{"content_uri":"mxc://localhost/0lRAO6q34if…"}

$ curl ".../r0/download/localhost/0lRAO6q34if…"
PNG bytes, Content-Type: image/png   [200]

$ curl .../r0/download/localhost/nope
{"errcode":"M_NOT_FOUND","error":"Media not found."} [404]
```

## Build & run

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```

## Study note

The media key packs three fields separated by 0xff and the download path
re-parses them by splitting on 0xff — exactly how upstream squeezed three
values into one KV key. A first translation bug (using `path_params` on a
regex route) caused 500s: regex captures live in `matches`, named params in
`path_params`.
