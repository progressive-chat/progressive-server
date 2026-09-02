# Step 67 — "Abstract event validation/fetching, add outlier and signing key DB trees" (Conduit `851eb55`)

Source: [`timokoesters/conduit@851eb55`](https://github.com/timokoesters/conduit/commit/851eb55) (2021-01-14)

## What changed vs step 66

| Rust change | C++ translation |
|---|---|
| **Abstract event validation/fetching** | **Translated** — Event validation abstraction |
| **Add outlier DB tree** | **Translated** — New outlier events tree |
| **Add signing key DB tree** | **Translated** — New signing key tree |
| **Major server_server refactor** | **Translated** — Cleaner server_server |

## Implementation details

1. **Event validation abstraction** — New event validation layer
2. **Outlier events tree** — New database tree for outlier events
3. **Signing key tree** — New database tree for signing keys
4. **Server server refactor** — Major refactor of server_server

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
