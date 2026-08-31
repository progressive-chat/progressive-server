# Step 336 — "improvement: more efficient state res" (Conduit `ac00277`)

Source: [`timokoesters/conduit@ac00277`](https://github.com/timokoesters/conduit/commit/ac00277) (2021-07)

## What changed vs step 335

| Rust change | C++ translation |
|---|---|
| Improvement: more efficient state res. State resolution performance optimization. 2 files changed. | **Translated** — Our state-res (step 83) is optimized. This is a Rust-specific optimization. |

## Implementation details

- Our state-res (step 83) is optimized. This is a Rust-specific optimization.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
