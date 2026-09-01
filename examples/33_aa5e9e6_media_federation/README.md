# Step 33 — "feat: download media and thumbnails over federation" (Conduit `aa5e9e6`)

Source: [`timokoesters/conduit@aa5e9e6`](https://github.com/timokoesters/conduit/commit/aa5e9e6) (2020-09-14)

## What changed vs step 32

| Rust change | C++ translation |
|---|---|
| **`get_content_route`** — fetches remote media if `allow_remote=true` | **Translated** — Added remote media fetch with `allow_remote` parameter |
| **`get_content_thumbnail_route`** — fetches remote thumbnails if `allow_remote=true` | **Translated** — Added remote thumbnail fetch with `allow_remote` parameter |
| **`Media::upload_thumbnail`** — new method to store thumbnails | **Translated** — Added `upload_thumbnail` method to database |
| **`Media::get`** — now takes `&str` instead of `String` | **Translated** — Updated signature |

## Implementation details

- **`get_content_route`**: When `allow_remote=true` and media not found locally, fetches from remote server, stores locally, returns content
- **`get_content_thumbnail_route`**: When `allow_remote=true` and thumbnail not found locally, fetches from remote server, stores locally, returns thumbnail
- **`upload_thumbnail`**: New database method to store thumbnails with width/height metadata
- **`Media::get`**: Now takes `const std::string&` instead of `std::string`

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
