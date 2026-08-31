# Step 359 — "improvement: allow rocksdb again" (Conduit `1d647a1`)

Source: [`timokoesters/conduit@1d647a1`](https://github.com/timokoesters/conduit/commit/1d647a1) (2022-01)

## What changed vs step 358

| Rust change | C++ translation |
|---|---|
| Improvement: allow rocksdb again. Re-enable RocksDB as database backend. 8 files changed. | **Translated** — Related to step 307/312 (swappable DB backend). RocksDB re-enabled. |

## Implementation details

- Related to step 307/312 (swappable DB backend). RocksDB re-enabled.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
