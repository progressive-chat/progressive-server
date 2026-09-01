# Step 598 — "improvement: handle restricted joins locally" (Conduit `2a04c21`)

Source: [`timokoesters/conduit@2a04c21`](https://github.com/timokoesters/conduit/commit/2a04c21) (2022-12)

## What changed vs step 597

| Rust change | C++ translation |
|---|---|
| Improvement: handle restricted joins locally. Process restricted room joins without federation when possible. 2 files changed. | **Translated** — Our restricted joins (step 564) work. This adds local handling optimization. |

## Implementation details

- Our restricted joins (step 564) work. This adds local handling optimization.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
