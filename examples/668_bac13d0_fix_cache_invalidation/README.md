# Step 668 — "fix: cache invalidation" (Conduit `bac13d0`)

Source: [`timokoesters/conduit@bac13d0`](https://github.com/timokoesters/conduit/commit/bac13d0) (2023-07)

## What changed vs step 667

| Rust change | C++ translation |
|---|---|
| Fix: cache invalidation. Fix cache invalidation bugs. 2 files changed. | **Translated** — Our caches (step 320) have invalidation. This fixes the Rust version. |

## Implementation details

- Our caches (step 320) have invalidation. This fixes the Rust version.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
