# Step 137 — "fix: also return successful PDUs in /send/:txnId" (Conduit `7db59c5`)

Source: [`timokoesters/conduit@7db59c5`](https://github.com/timokoesters/conduit/commit/7db59c5) (2021-05-27)

## What changed vs step 136

| Rust change | C++ translation |
|---|---|
| **Return successful PDUs in /send/:txnId** | **Translated** — Return successful PDUs |

## Implementation details

1. **Return successful PDUs** — Also return successful PDUs in /send/:txnId

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
