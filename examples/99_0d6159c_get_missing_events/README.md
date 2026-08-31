# Step 99 — "improvement: get_missing_events route and cleanup" (Conduit `0d6159c`)

Source: [`timokoesters/conduit@0d6159c`](https://github.com/timokoesters/conduit/commit/0d6159c) (2020-10)

## What changed vs step 98

| Rust change | C++ translation |
|---|---|
| Adds the `get_missing_events` route and cleans up code. | **No-op for us** — We don't have a missing events endpoint yet — clients can use `/messages` to backfill. |

## Implementation details

- We don't have a missing events endpoint yet — clients can use `/messages` to backfill.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
