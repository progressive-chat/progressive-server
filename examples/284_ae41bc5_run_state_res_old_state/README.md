# Step 284 — "fix: run state res with old current state again" (Conduit `ae41bc5`)

Source: [`timokoesters/conduit@ae41bc5`](https://github.com/timokoesters/conduit/commit/ae41bc5) (2021-05)

## What changed vs step 283

| Rust change | C++ translation |
|---|---|
| Fix: run state res with old current state again. State resolution re-runs with previous state on failure. | **Translated** — Our state-res (step 83) handles retries. This is a specific fix for re-running with old state. |

## Implementation details

- Our state-res (step 83) handles retries. This is a specific fix for re-running with old state.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
