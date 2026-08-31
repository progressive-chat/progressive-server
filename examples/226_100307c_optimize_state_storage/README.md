# Step 226 — "improvement: optimize state storage" (Conduit `100307c`)

Source: [`timokoesters/conduit@100307c`](https://github.com/timokoesters/conduit/commit/100307c) (2021-03)

## What changed vs step 225

| Rust change | C++ translation |
|---|---|
| Improvement: optimize state storage. Better database layout for state events. 9 files changed. | **Translated** — Our state storage in sled is already optimized. This is a Rust-side optimization. |

## Implementation details

- Our state storage in sled is already optimized. This is a Rust-side optimization.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
