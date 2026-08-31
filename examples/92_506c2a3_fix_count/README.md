# Step 92 — "fix: can't find count from event in db" (Conduit `506c2a3`)

Source: [`timokoesters/conduit@506c2a3`](https://github.com/timokoesters/conduit/commit/506c2a3) (2020-09)

## What changed vs step 91

| Rust change | C++ translation |
|---|---|
| Fix: `/sync` couldn't find the count from a PDU in the database. Adds a fallback to look up the count by event_id. | Our step 18 (`b4d65ab6_sync_optimize`) covers this fix in the /sync handler. |

## Implementation details

- Our step 18 (`b4d65ab6_sync_optimize`) covers this fix in the /sync handler.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
