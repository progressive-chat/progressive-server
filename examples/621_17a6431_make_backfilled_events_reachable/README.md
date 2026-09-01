# Step 621 — "fix: make backfilled events reachable" (Conduit `17a6431`)

Source: [`timokoesters/conduit@17a6431`](https://github.com/timokoesters/conduit/commit/17a6431) (2023-03)

## What changed vs step 620

| Rust change | C++ translation |
|---|---|
| Fix: make backfilled events reachable. Ensure backfilled events are in the DAG. 3 files changed. | **Translated** — Backfill events need to be linked. This fixes the Rust version. |

## Implementation details

- Backfill events need to be linked. This fixes the Rust version.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
