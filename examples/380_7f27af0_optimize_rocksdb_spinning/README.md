# Step 380 — "improvement: optimize rocksdb for spinning disks" (Conduit `7f27af0`)

Source: [`timokoesters/conduit@7f27af0`](https://github.com/timokoesters/conduit/commit/7f27af0) (2022-01)

## What changed vs step 379

| Rust change | C++ translation |
|---|---|
| Improvement: optimize rocksdb for spinning disks. HDD-optimized RocksDB settings. | **Translated** — RocksDB tuning for HDD — our default is SSD. Config option would be new. |

## Implementation details

- RocksDB tuning for HDD — our default is SSD. Config option would be new.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
