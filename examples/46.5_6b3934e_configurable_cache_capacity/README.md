# Step 46.5 — "feat: configurable cache capacity" (Conduit `6b3934e`)

Source: [`timokoesters/conduit@6b3934e`](https://github.com/timokoesters/conduit/commit/6b3934e) (2020-10-23)

## What changed vs step 46

| Rust change | C++ translation |
|---|---|
| **Configurable sled cache capacity** via `cache_capacity` config option | **Translated** — Implemented actual cache capacity configuration for RocksDB |
| **Default 1GB cache** with configurable override | **Translated** — Default 1GB, configurable via Data constructor |

## Implementation details

1. **Added `cache_capacity` parameter** to Data constructor (default 1GB)
2. **Updated RocksDB options** to use configurable cache capacity via `set_table_factory` with `BlockBasedTable` and `BlockCache`
4. **Disabled default cache** behavior to allow custom cache configuration

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```