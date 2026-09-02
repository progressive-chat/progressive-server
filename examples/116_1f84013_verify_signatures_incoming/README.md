# Step 116 — "feat: verify signatures for incoming requests" (Conduit `1f84013`)

Source: [`timokoesters/conduit@1f84013`](https://github.com/timokoesters/conduit/commit/1f84013) (2021-04-21)

## What changed vs step 115

| Rust change | C++ translation |
|---|---|
| **Verify signatures for incoming requests** | **Translated** — Verify signatures |

## Implementation details

1. **Signature verification** — Verify signatures for incoming requests

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
