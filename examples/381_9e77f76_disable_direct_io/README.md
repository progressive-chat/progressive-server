# Step 381 — "fix: disable direct IO again" (Conduit `9e77f76`)

Source: [`timokoesters/conduit@9e77f76`](https://github.com/timokoesters/conduit/commit/9e77f76) (2022-01)

## What changed vs step 380

| Rust change | C++ translation |
|---|---|
| Fix: disable direct IO again. Direct IO setting for RocksDB. | **Translated** — RocksDB direct IO toggle — config option. |

## Implementation details

- RocksDB direct IO toggle — config option.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
