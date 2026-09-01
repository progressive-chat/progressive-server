# Step 637 — "fix: don't accept new requests when shutting down" (Conduit `2a7c469`)

Source: [`timokoesters/conduit@2a7c469`](https://github.com/timokoesters/conduit/commit/2a7c469) (2023-03)

## What changed vs step 636

| Rust change | C++ translation |
|---|---|
| Fix: don't accept new requests when shutting down. Graceful shutdown request rejection. 2 files changed. | **Translated** — Our server (step 631) has graceful shutdown. This adds request rejection. |

## Implementation details

- Our server (step 631) has graceful shutdown. This adds request rejection.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
