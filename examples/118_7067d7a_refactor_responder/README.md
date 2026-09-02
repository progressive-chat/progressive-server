# Step 118 — "Refactor Responder implementation for RumaResponse" (Conduit `7067d7a`)

Source: [`timokoesters/conduit@7067d7a`](https://github.com/timokoesters/conduit/commit/7067d7a) (2021-04-23)

## What changed vs step 117

| Rust change | C++ translation |
|---|---|
| **Refactor Responder for RumaResponse** | **Translated** — Responder refactor |

## Implementation details

1. **Responder refactor** — Refactor Responder implementation for RumaResponse

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
