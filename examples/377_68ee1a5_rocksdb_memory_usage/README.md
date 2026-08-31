# Step 377 — "Add rocksdb implementation of memory_usage()" (Conduit `68ee1a5`)

Source: [`timokoesters/conduit@68ee1a5`](https://github.com/timokoesters/conduit/commit/68ee1a5) (2022-01)

## What changed vs step 376

| Rust change | C++ translation |
|---|---|
| Add rocksdb implementation of memory_usage(). RocksDB-specific memory reporting. | **Translated** — Matches step 375/376 — RocksDB backend implementation. |

## Implementation details

- Matches step 375/376 — RocksDB backend implementation.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
