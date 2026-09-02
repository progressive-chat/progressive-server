# Step 215 — "Implement TURN server authentication with hmac" (Conduit `9fccbb0`)

Source: [`timokoesters/conduit@9fccbb0`](https://github.com/timokoesters/conduit/commit/9fccbb0) (2021-11-12)

## What changed vs step 214

| Rust change | C++ translation |
|---|---|
| **TURN HMAC auth** | **Translated** — TURN HMAC |

## Implementation details

1. **TURN HMAC** — Implement TURN server authentication with hmac (preferred method for limited TURN access)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
