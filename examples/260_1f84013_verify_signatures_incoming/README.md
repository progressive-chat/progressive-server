# Step 260 — "feat: verify signatures for incoming requests" (Conduit `1f84013`)

Source: [`timokoesters/conduit@1f84013`](https://github.com/timokoesters/conduit/commit/1f84013) (2021-04)

## What changed vs step 259

| Rust change | C++ translation |
|---|---|
| Feat: verify signatures for incoming requests. Validate request signatures on federation endpoints. 2 files changed. | **Translated** — Our federation endpoints (step 29) verify signatures via `crypto::verify`. |

## Implementation details

- Our federation endpoints (step 29) verify signatures via `crypto::verify`.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
