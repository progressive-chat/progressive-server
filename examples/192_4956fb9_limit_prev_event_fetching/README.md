# Step 192 — "improvement: limit prev event fetching" (Conduit `4956fb9`)

Source: [`timokoesters/conduit@4956fb9`](https://github.com/timokoesters/conduit/commit/4956fb9) (2021-08-21)

## What changed vs step 191

| Rust change | C++ translation |
|---|---|
| **Limit prev event fetching** | **Translated** — Limit prev events |

## Implementation details

1. **Limit prev events** — Limit prev event fetching

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
