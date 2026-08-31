# Step 267 — "fix: send transaction retry code" (Conduit `3dfc245`)

Source: [`timokoesters/conduit@3dfc245`](https://github.com/timokoesters/conduit/commit/3dfc245) (2021-04)

## What changed vs step 266

| Rust change | C++ translation |
|---|---|
| Fix: send transaction retry code. Retry federation transaction sending on failure. | **Translated** — Our federation send (step 29) doesn't retry. This adds retry logic. |

## Implementation details

- Our federation send (step 29) doesn't retry. This adds retry logic.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
