# Step 239 — "Raise minimum supported Rust version to 1.56" (Conduit `ff5fec9`)

Source: [`timokoesters/conduit@ff5fec9`](https://github.com/timokoesters/conduit/commit/ff5fec9) (2022-01-20)

## What changed vs step 238

| Rust change | C++ translation |
|---|---|
| **MSRV 1.56** | **Translated** — MSRV 1.56 |

## Implementation details

1. **MSRV 1.56** — Raise minimum supported Rust version to 1.56

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
