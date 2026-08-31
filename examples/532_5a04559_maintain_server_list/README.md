# Step 532 — "fix: maintain server list again" (Conduit `5a04559`)

Source: [`timokoesters/conduit@5a04559`](https://github.com/timokoesters/conduit/commit/5a04559) (2022-10)

## What changed vs step 531

| Rust change | C++ translation |
|---|---|
| Fix: maintain server list again. Federation server list maintenance. 2 files changed. | **Translated** — Our federation (step 29) maintains server list. This fixes the Rust version. |

## Implementation details

- Our federation (step 29) maintains server list. This fixes the Rust version.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
