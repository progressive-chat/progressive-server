# Step 318 — "improvement: /search works for multiple rooms" (Conduit `dcac136`)

Source: [`timokoesters/conduit@dcac136`](https://github.com/timokoesters/conduit/commit/dcac136) (2021-06)

## What changed vs step 317

| Rust change | C++ translation |
|---|---|
| Improvement: /search works for multiple rooms. Search across multiple rooms at once. | **Translated** — We don't have /search yet. This adds multi-room search. |

## Implementation details

- We don't have /search yet. This adds multi-room search.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
