# Step 294 — "feat: forward federation errors to the client" (Conduit `e5c7119`)

Source: [`timokoesters/conduit@e5c7119`](https://github.com/timokoesters/conduit/commit/e5c7119) (2021-05)

## What changed vs step 293

| Rust change | C++ translation |
|---|---|
| Feat: forward federation errors to the client. Return federation errors to clients instead of generic errors. 2 files changed. | **Translated** — Our federation errors (step 29) are returned to clients. This ensures proper error propagation. |

## Implementation details

- Our federation errors (step 29) are returned to clients. This ensures proper error propagation.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
