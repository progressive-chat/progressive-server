# Step 96 — "Send proper Host header in federation requests" (Conduit `7b3fe88`)

Source: [`timokoesters/conduit@7b3fe88`](https://github.com/timokoesters/conduit/commit/7b3fe88) (2021-03-18)

## What changed vs step 95

| Rust change | C++ translation |
|---|---|
| **Send proper Host header** | **Translated** — Proper Host header |

## Implementation details

1. **Host header** — Send proper Host header in federation requests

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
