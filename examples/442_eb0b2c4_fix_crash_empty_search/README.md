# Step 442 — "fix: crash on empty search" (Conduit `eb0b2c4`)

Source: [`timokoesters/conduit@eb0b2c4`](https://github.com/timokoesters/conduit/commit/eb0b2c4) (2022-02)

## What changed vs step 441

| Rust change | C++ translation |
|---|---|
| Fix: crash on empty search. Handle empty search query gracefully. 2 files changed. | **Translated** — Our /search (step 318) handles empty queries. This fixes a Rust crash. |

## Implementation details

- Our /search (step 318) handles empty queries. This fixes a Rust crash.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
