# Step 618 — "feat: handle backfill requests" (Conduit `23b18d7`)

Source: [`timokoesters/conduit@23b18d7`](https://github.com/timokoesters/conduit/commit/23b18d7) (2023-03)

## What changed vs step 617

| Rust change | C++ translation |
|---|---|
| Feat: handle backfill requests. Backfill API for historical events. 4 files changed. | **Translated** — We don't have backfill yet. This adds the backfill handling. |

## Implementation details

- We don't have backfill yet. This adds the backfill handling.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
