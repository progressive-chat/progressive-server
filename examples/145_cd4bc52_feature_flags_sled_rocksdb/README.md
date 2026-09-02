# Step 145 — "improvement: feature flags for sled, rocksdb" (Conduit `cd4bc52`)

Source: [`timokoesters/conduit@cd4bc52`](https://github.com/timokoesters/conduit/commit/cd4bc52) (2021-06-12)

## What changed vs step 144

| Rust change | C++ translation |
|---|---|
| **Feature flags for sled, rocksdb** | **Translated** — Database feature flags |

## Implementation details

1. **Database feature flags** — Add feature flags for sled, rocksdb

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
