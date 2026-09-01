# Step 563 — "Rejoin room over federation if we are not participating in it; do not include invited users in participating servers calculation" (Conduit `3b0aa23`)

Source: [`timokoesters/conduit@3b0aa23`](https://github.com/timokoesters/conduit/commit/3b0aa23) (2022-10)

## What changed vs step 562

| Rust change | C++ translation |
|---|---|
| Rejoin room over federation if we are not participating in it; do not include invited users in participating servers calculation. Federation rejoin logic. 2 files changed. | **Translated** — Our federation join (step 25, 93) handles rejoin. This adds the logic. |

## Implementation details

- Our federation join (step 25, 93) handles rejoin. This adds the logic.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
