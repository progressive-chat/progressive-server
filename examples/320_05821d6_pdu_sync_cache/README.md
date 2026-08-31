# Step 320 — "improvement: pdu cache, /sync cache" (Conduit `05821d6`)

Source: [`timokoesters/conduit@05821d6`](https://github.com/timokoesters/conduit/commit/05821d6) (2021-06)

## What changed vs step 319

| Rust change | C++ translation |
|---|---|
| Improvement: pdu cache, /sync cache. Caching layer for PDUs and /sync responses. 16 files changed. MAJOR performance. | **Translated** — Our /sync (step 6) doesn't have a cache. This adds PDU and sync caching. |

## Implementation details

- Our /sync (step 6) doesn't have a cache. This adds PDU and sync caching.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
