# Step 803 — "put media in filesystem" (Conduit `972caacd`)

Source: [`timokoesters/conduit@972caacd`](https://github.com/timokoesters/conduit/commit/972caacd) (2021-06-04)

Straight-order intermediate `bb7a4220` (Cargo-only ruma bump) has no code
change. The `Send`-bound trait tweaks in the same commit don't apply (no
async/sled-trait layer in C++).

## What changed vs step 802

| Rust change | C++ translation |
|---|---|
| **Blobs in `<db>/media/<base64url(key)>` files; tree keeps metadata** | **Implemented** — `Media::set_dir()` (`<data_dir>/media`), `store_bytes`/`load_bytes`; `create`/`upload_thumbnail` write files + empty tree values; `get` reads the file |
| **`get_media_folder` / `get_media_file` on globals** | **Implemented** — `Media::file_path()` (same layout); dir created on demand |
| **Old inline blobs** | **Better than upstream** — no migration upstream (orphans blobs); C++ falls back to inline tree bytes when the file is missing, so pre-step-124 uploads keep serving |

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server
```
