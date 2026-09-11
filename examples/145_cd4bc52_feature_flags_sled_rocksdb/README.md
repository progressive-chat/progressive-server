# Step 145 — "improvement: feature flags for sled, rocksdb" (Conduit `cd4bc52`)

Source: [`timokoesters/conduit@cd4bc52`](https://github.com/timokoesters/conduit/commit/cd4bc52) (2021-06-12)

Upstream adds Cargo feature flags to select the storage backend
(`sled` vs `rocksdb`).

## What changed vs step 144

**Nothing in `src/` — this directory was a byte-identical copy.** This port
has a single storage backend (RocksDB, behind the `sled::Db` adapter), so
there is no backend choice to put behind a flag. The CMake build already
prefers a system RocksDB and falls back to building it from source.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit145 && ./build/tests
```
