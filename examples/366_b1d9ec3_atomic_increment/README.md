# Step 366 — "fix: atomic increment" (Conduit `b1d9ec3`)

Source: [`timokoesters/conduit@b1d9ec3`](https://github.com/timokoesters/conduit/commit/b1d9ec3) (2022-01)

## What changed vs step 365

| Rust change | C++ translation |
|---|---|
| Fix: atomic increment. Thread-safe counter fix. 3 files changed. | **Translated** — Our counters use atomic operations. This fixes a Rust atomic issue. |

## Implementation details

- Our counters use atomic operations. This fixes a Rust atomic issue.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
