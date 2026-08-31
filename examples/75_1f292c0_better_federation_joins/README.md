# Step 75 — "improvement: better federation joins" (Conduit `1f292c0`)

Source: [`timokoesters/conduit@1f292c0`](https://github.com/timokoesters/conduit/commit/1f292c0) (2020-09)

## What changed vs step 74

| Rust change | C++ translation |
|---|---|
| Improves the federation `/send_join` response by adding additional state events. | Our step 29 (`12a8c9ba_federation_join`) implements the full federation join with state events. |

## Implementation details

- Our step 29 (`12a8c9ba_federation_join`) implements the full federation join with state events.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
