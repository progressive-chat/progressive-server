# Step 129 — "fix: unauthorized pdus will be responded to with FORBIDDEN" (Conduit `989d843`)

Source: [`timokoesters/conduit@989d843`](https://github.com/timokoesters/conduit/commit/989d843) (2021-05-21)

## What changed vs step 128

| Rust change | C++ translation |
|---|---|
| **Unauthorized PDUs → FORBIDDEN** | **Translated** — FORBIDDEN response |

## Implementation details

1. **FORBIDDEN response** — Unauthorized PDUs will be responded to with FORBIDDEN

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
