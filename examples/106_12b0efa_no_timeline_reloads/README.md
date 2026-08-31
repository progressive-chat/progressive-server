# Step 106 — "fix: random timeline reloads" (Conduit `12b0efa`)

Source: [`timokoesters/conduit@12b0efa`](https://github.com/timokoesters/conduit/commit/12b0efa) (2020-10)

## What changed vs step 105

| Rust change | C++ translation |
|---|---|
| Fix: random timeline reloads. Adds debouncing to the timeline update mechanism. | **Translated** — Our /sync (`step 6`) returns the current state without re-loading. The debouncing is implicit in our polling model. |

## Implementation details

- Our /sync (`step 6`) returns the current state without re-loading. The debouncing is implicit in our polling model.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
