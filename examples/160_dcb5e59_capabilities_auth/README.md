# Step 160 — "Getting capabilities requires authentication" (Conduit `dcb5e59`)

Source: [`timokoesters/conduit@dcb5e59`](https://github.com/timokoesters/conduit/commit/dcb5e59) (2021-07-11)

## What changed vs step 159

| Rust change | C++ translation |
|---|---|
| **Capabilities requires auth** | **Translated** — Capabilities auth |

## Implementation details

1. **Capabilities auth** — Getting capabilities now requires authentication

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
