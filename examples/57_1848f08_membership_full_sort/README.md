# Step 57 — "Use full sorting algorithm on incoming PDU's in membership" (Conduit `1848f08`)

Source: [`timokoesters/conduit@1848f08`](https://github.com/timokoesters/conduit/commit/1848f08) (2020-08)

## What changed vs step 56

| Rust change | C++ translation |
|---|---|
| Uses the full state-res sorting algorithm on incoming membership PDUs from `/send_join` instead of a simple sort. | **Partial** — our `state_res.cpp` (from step 45/83) handles the sorting but this specific change is folded into the larger state-res refactor. |

## Implementation details

- **Partial** — our `state_res.cpp` (from step 45/83) handles the sorting but this specific change is folded into the larger state-res refactor.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
