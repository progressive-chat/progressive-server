# Step 173 — "improvement: allow batch inserts" (Conduit `49ade0c`)

Source: [`timokoesters/conduit@49ade0c`](https://github.com/timokoesters/conduit/commit/49ade0c) (2021-08-03)

## What changed vs step 172

| Rust change | C++ translation |
|---|---|
| **Allow batch inserts** | **Translated** — Batch inserts |

## Implementation details

1. **Batch inserts** — Allow batch inserts in database

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
