# Step 378 — "improvement: memory usage for caches" (Conduit `077e9ad`)

Source: [`timokoesters/conduit@077e9ad`](https://github.com/timokoesters/conduit/commit/077e9ad) (2022-01)

## What changed vs step 377

| Rust change | C++ translation |
|---|---|
| Improvement: memory usage for caches. Cache memory tracking and reporting. 4 files changed. | **Translated** — Our caches don't report memory. This adds cache memory tracking. |

## Implementation details

- Our caches don't report memory. This adds cache memory tracking.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
