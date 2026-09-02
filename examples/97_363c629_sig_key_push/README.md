# Step 97 — "fix: signature key fetching, optimize push sending" (Conduit `363c629`)

Source: [`timokoesters/conduit@363c629`](https://github.com/timokoesters/conduit/commit/363c629) (2021-03-22)

## What changed vs step 96

| Rust change | C++ translation |
|---|---|
| **Signature key fetching fix** | **Translated** — Signature key fixes |
| **Optimize push sending** | **Translated** — Push sending optimization |
| **Major pusher refactor** | **Translated** — Pusher refactor |
| **Major sending refactor** | **Translated** — Sending refactor |

## Implementation details

1. **Signature key fixes** — Fix signature key fetching
2. **Push sending optimization** — Optimize push sending
3. **Major pusher refactor** — Major refactor of pusher database
4. **Major sending refactor** — Major refactor of sending code

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
