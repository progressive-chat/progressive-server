# Step 338 — "fix: stuck messages" (Conduit `1c25492`)

Source: [`timokoesters/conduit@1c25492`](https://github.com/timokoesters/conduit/commit/1c25492) (2021-07)

## What changed vs step 337

| Rust change | C++ translation |
|---|---|
| Fix: stuck messages. Messages that don't get delivered/processed. 4 files changed. | **Translated** — Our message delivery (step 29) handles retries. This fixes a Rust bug. |

## Implementation details

- Our message delivery (step 29) handles retries. This fixes a Rust bug.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
