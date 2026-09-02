# Step 214 — "Implement turn server settings" (Conduit `109892b`)

Source: [`timokoesters/conduit@109892b`](https://github.com/timokoesters/conduit/commit/109892b) (2021-11-12)

## What changed vs step 213

| Rust change | C++ translation |
|---|---|
| **Turn server settings** | **Translated** — Turn server settings |

## Implementation details

1. **Turn server settings** — Implement turn server settings, fills out /_matrix/client/r0/voip/turnServer with values from server config

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
