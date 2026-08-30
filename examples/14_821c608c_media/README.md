# Step 14 — "feat: media" (Conduit `821c608c`)

Source: [`timokoesters/conduit@821c608c`](https://github.com/timokoesters/conduit/commit/821c608c) (2020-05-18)

## What changed vs step 13

| Rust change | C++ translation |
|---|---|
| Adds the media repository: `mxc://` upload, download, and thumbnails. New `database/media.rs` with `Media { mediaid_file }` tree; keys are MXC+0xff+filename+0xff+content_type. `GET /_matrix/media/r0/config` returns 20 MB upload size. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
