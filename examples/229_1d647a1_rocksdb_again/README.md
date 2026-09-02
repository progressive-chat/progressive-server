# Step 229 — "improvement: allow rocksdb again" (Conduit `1d647a1`)

Source: [`timokoesters/conduit@1d647a1`](https://github.com/timokoesters/conduit/commit/1d647a1) (2022-01-13)

## What changed vs step 228

| Rust change | C++ translation |
|---|---|
| **Allow rocksdb again** | **Translated** — Rocksdb again |

## Implementation details

1. **Rocksdb again** — Allow rocksdb again

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
