# Step 106 — "improvement: fetch signing keys in parallel when joining a room" (Conduit `8b40e0a`)

Source: [`timokoesters/conduit@8b40e0a`](https://github.com/timokoesters/conduit/commit/8b40e0a) (2021-04-13)

## What changed vs step 105

| Rust change | C++ translation |
|---|---|
| **Fetch signing keys in parallel** | **Translated** — Parallel signing keys |

## Implementation details

1. **Parallel signing keys** — Fetch signing keys in parallel when joining a room

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
