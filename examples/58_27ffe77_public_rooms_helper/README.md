# Step 58 — "Use helper instead of route for get_public_rooms_filtered" (Conduit `27ffe77`)

Source: [`timokoesters/conduit@27ffe77`](https://github.com/timokoesters/conduit/commit/27ffe77) (2020-08)

## What changed vs step 57

| Rust change | C++ translation |
|---|---|
| Replaces the `get_public_rooms_filtered_route` with a helper function so it can be reused. | **No-op for us** — our public rooms endpoint (from step 22) doesn't have this refactor yet, but the behavior is correct. |

## Implementation details

- **No-op for us** — our public rooms endpoint (from step 22) doesn't have this refactor yet, but the behavior is correct.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
