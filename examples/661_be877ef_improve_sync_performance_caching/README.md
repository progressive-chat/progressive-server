# Step 661 — "Improve sync performance with more caching and wrapping things in Arcs to avoid copies" (Conduit `be877ef`)

Source: [`timokoesters/conduit@be877ef`](https://github.com/timokoesters/conduit/commit/be877ef) (2023-06)

## What changed vs step 660

| Rust change | C++ translation |
|---|---|
| Improve sync performance with more caching and wrapping things in Arcs to avoid copies. Sync performance optimization. 12 files changed. MAJOR perf. | **Translated** — Our /sync (step 6, 320) has caching. This adds more caching and Arc optimization in Rust. |

## Implementation details

- Our /sync (step 6, 320) has caching. This adds more caching and Arc optimization in Rust.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
