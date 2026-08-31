# Step 371 — "improvement: faster way to load required state" (Conduit `93d225f`)

Source: [`timokoesters/conduit@93d225f`](https://github.com/timokoesters/conduit/commit/93d225f) (2022-01)

## What changed vs step 370

| Rust change | C++ translation |
|---|---|
| Improvement: faster way to load required state. State loading optimization. 1 file changed. | **Translated** — Our state loading (step 83) is optimized. This is a Rust-specific optimization. |

## Implementation details

- Our state loading (step 83) is optimized. This is a Rust-specific optimization.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
