# Step 181 — "improvement: smaller cache, better prev event fetching" (Conduit `096e097`)

Source: [`timokoesters/conduit@096e097`](https://github.com/timokoesters/conduit/commit/096e097) (2021-08-12)

## What changed vs step 180

| Rust change | C++ translation |
|---|---|
| **Smaller cache, better prev event fetching** | **Translated** — Better cache and prev events |

## Implementation details

1. **Smaller cache** — Smaller cache
2. **Better prev event fetching** — Better prev event fetching

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
