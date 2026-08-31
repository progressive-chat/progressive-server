# Step 222 — "Query for the correct server" (Conduit `e239014`)

Source: [`timokoesters/conduit@e239014`](https://github.com/timokoesters/conduit/commit/e239014) (2021-03)

## What changed vs step 221

| Rust change | C++ translation |
|---|---|
| Query for the correct server. When fetching keys or events, pick the right server to ask. | **Translated** — Our federation client picks the origin server. This adds smarter server selection. |

## Implementation details

- Our federation client picks the origin server. This adds smarter server selection.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
