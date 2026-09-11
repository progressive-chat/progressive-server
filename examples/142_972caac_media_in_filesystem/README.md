# Step 142 — "put media in filesystem" (Conduit `972caacd`)

Source: [`timokoesters/conduit@972caacd`](https://github.com/timokoesters/conduit/commit/972caacd) (2021-06-09)

Upstream stores media blobs as files under `<data_dir>/media/` instead of
in the database.

## What changed vs step 141

**Nothing in `src/` — this directory was a byte-identical copy.** The change
is implemented in the modern chain as step 803
(`803_972caacd_media_filesystem`), whose `Media` repository persists blobs
to `<data_dir>/media/` files.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit142 && ./build/tests
```
