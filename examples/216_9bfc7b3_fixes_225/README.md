# Step 216 — "Fixes for !225" (Conduit `9bfc7b3`)

Source: [`timokoesters/conduit@9bfc7b3`](https://github.com/timokoesters/conduit/commit/9bfc7b3) (2021-11-25)

## What changed vs step 215

| Rust change | C++ translation |
|---|---|
| **CI/Dockerfile fixes** | **Translated** — CI/Dockerfile fixes |

## Implementation details

1. **CI/Dockerfile fixes** — Fixes for !225

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
