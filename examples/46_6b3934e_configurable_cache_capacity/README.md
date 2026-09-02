# Step 46 — "feat: configurable cache capacity" (Conduit `6b3934e`)

Source: [`timokoesters/conduit@6b3934e`](https://github.com/timokoesters/conduit/commit/6b3934e) (2020-10-23)

## What changed vs step 45

| Rust change | C++ translation |
|---|---|
| **Configurable sled cache capacity** via `cache_capacity` config option | **Translated** — Added `cache_capacity` config option |
| **Default 1GB cache** with configurable override | **Translated** — Default 1GB, configurable via config file |
| **Disabled sled default features** (to allow cache configuration) | **Translated** — Updated build to support cache configuration |

## Implementation details

1. **Added `cache_capacity` config option** (default 1GB)
2. **Updated sled config** to use configurable cache capacity
3. **Disabled sled default features** to allow cache configuration

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
