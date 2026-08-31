# Step 385 — "feat: config option for rocksdb max open files" (Conduit `d434dfb`)

Source: [`timokoesters/conduit@d434dfb`](https://github.com/timokoesters/conduit/commit/d434dfb) (2022-01)

## What changed vs step 384

| Rust change | C++ translation |
|---|---|
| Feat: config option for rocksdb max open files. File descriptor limit config. 2 files changed. | **Translated** — RocksDB max_open_files config — our DB doesn't expose this yet. |

## Implementation details

- RocksDB max_open_files config — our DB doesn't expose this yet.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
