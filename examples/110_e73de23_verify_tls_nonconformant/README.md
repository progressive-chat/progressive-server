# Step 110 — "fix: verify tls cert for non-conformant servers" (Conduit `e73de23`)

Source: [`timokoesters/conduit@e73de23`](https://github.com/timokoesters/conduit/commit/e73de23) (2021-04-16)

## What changed vs step 109

| Rust change | C++ translation |
|---|---|
| **Verify TLS cert for non-conformant servers** | **Translated** — TLS cert verification |

## Implementation details

1. **TLS cert verification** — Verify TLS cert for non-conformant servers

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
