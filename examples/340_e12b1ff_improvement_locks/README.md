# Step 340 — "improvement: locks" (Conduit `e12b1ff`)

Source: [`timokoesters/conduit@e12b1ff`](https://github.com/timokoesters/conduit/commit/e12b1ff) (2021-07)

## What changed vs step 339

| Rust change | C++ translation |
|---|---|
| Improvement: locks. Better locking strategy for concurrent access. 12 files changed. | **Translated** — Our sled database handles locking. This improves Rust lock patterns. |

## Implementation details

- Our sled database handles locking. This improves Rust lock patterns.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
