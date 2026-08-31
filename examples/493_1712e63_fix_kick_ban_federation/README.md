# Step 493 — "fix: fix kick and ban events over federation" (Conduit `1712e63`)

Source: [`timokoesters/conduit@1712e63`](https://github.com/timokoesters/conduit/commit/1712e63) (2022-04)

## What changed vs step 492

| Rust change | C++ translation |
|---|---|
| Fix: fix kick and ban events over federation. Federation moderation events. 1 file changed. | **Translated** — Our federation (step 29) handles kick/ban. This fixes the Rust implementation. |

## Implementation details

- Our federation (step 29) handles kick/ban. This fixes the Rust implementation.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
