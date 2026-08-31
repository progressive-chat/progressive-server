# Step 379 — "improvement: rocksdb configuration" (Conduit `0bb7d76`)

Source: [`timokoesters/conduit@0bb7d76`](https://github.com/timokoesters/conduit/commit/0bb7d76) (2022-01)

## What changed vs step 378

| Rust change | C++ translation |
|---|---|
| Improvement: rocksdb configuration. Better RocksDB tuning options. 1 file changed. | **Translated** — Related to step 359/360 (rocksdb). Adds configuration options. |

## Implementation details

- Related to step 359/360 (rocksdb). Adds configuration options.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
