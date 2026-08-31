# Step 460 — "Add a not-found route" (Conduit `3aece38`)

Source: [`timokoesters/conduit@3aece38`](https://github.com/timokoesters/conduit/commit/3aece38) (2022-02)

## What changed vs step 459

| Rust change | C++ translation |
|---|---|
| Add a not-found route. 404 handler for unknown routes. | **Translated** — Our server (step 6) has a catch-all 404. This adds it in Rust. |

## Implementation details

- Our server (step 6) has a catch-all 404. This adds it in Rust.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
