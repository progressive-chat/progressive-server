# Step 360 — "rocksdb as default" (Conduit `a30b588`)

Source: [`timokoesters/conduit@a30b588`](https://github.com/timokoesters/conduit/commit/a30b588) (2022-01)

## What changed vs step 359

| Rust change | C++ translation |
|---|---|
| RocksDB as default. Change default database backend to RocksDB. 2 files changed. | **Translated** — Our default is sled. This changes default to RocksDB in Rust. |

## Implementation details

- Our default is sled. This changes default to RocksDB in Rust.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
