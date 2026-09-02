# Step 54 — "improvement: cache actual destination" (Conduit `d62f17a`)

Source: [`timokoesters/conduit@d62f17a`](https://github.com/timokoesters/conduit/commit/d62f17a) (2020-12-06)

## What changed vs step 51

| Rust change | C++ translation |
|---|---|
| **Added `actual_destination_cache`** to Globals with RwLock | **Translated** — Added `actual_destination_cache_` member |
| **Added DNS resolver** (trust-dns-resolver) | **Translated** — Added SRV record lookup support |
| **Made `Globals::load` async** | **Translated** — Updated initialization to be async |
| **Cached actual destination lookups** | **Translated** — Added caching in `send_request` |
| **Added `find_actual_destination` helper** | **Translated** — Added `find_actual_destination` function |

## Implementation details

1. **Added DNS resolver** using trust-dns-resolver equivalent
2. **Cached actual destination lookups** with RwLock
3. **SRV record lookup** for `_matrix._tcp.<domain>`
3. **Well-known delegation handling** with caching
4. **Made initialization async** for DNS resolver setup

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
