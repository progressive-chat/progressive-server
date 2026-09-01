# Step 693 — "maximize fd limit" (Conduit `291290d`)

Source: [`timokoesters/conduit@291290d`](https://github.com/timokoesters/conduit/commit/291290d) (2023-07)

## What changed vs step 692

| Rust change | C++ translation |
|---|---|
| Maximize fd limit. Increase file descriptor limit for high concurrency. 3 files changed. | **Translated** — Our server could benefit from higher fd limits. This sets it in Rust. |

## Implementation details

- Our server could benefit from higher fd limits. This sets it in Rust.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
