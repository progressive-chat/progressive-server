# Step 220 — "Use String to store UserId for uiaa request" (Conduit `720a54b`)

Source: [`timokoesters/conduit@720a54b`](https://github.com/timokoesters/conduit/commit/720a54b) (2021-12-18)

## What changed vs step 219

| Rust change | C++ translation |
|---|---|
| **String UserId for UIAA** | **Translated** — String UserId for UIAA |

## Implementation details

1. **String UserId for UIAA** — Use String to store UserId for uiaa request (fixes compilation error after ruma upgrade)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
