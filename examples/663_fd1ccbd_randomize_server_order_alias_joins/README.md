# Step 663 — "improvement: randomize server order for alias joins" (Conduit `fd1ccbd`)

Source: [`timokoesters/conduit@fd1ccbd`](https://github.com/timokoesters/conduit/commit/fd1ccbd) (2023-06)

## What changed vs step 662

| Rust change | C++ translation |
|---|---|
| Improvement: randomize server order for alias joins. Load balancing for alias resolution. 2 files changed. | **Translated** — Our alias resolution (step 10) picks servers. This randomizes the order. |

## Implementation details

- Our alias resolution (step 10) picks servers. This randomizes the order.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
