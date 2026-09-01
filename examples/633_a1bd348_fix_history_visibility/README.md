# Step 633 — "fix: history visibility" (Conduit `a1bd348`)

Source: [`timokoesters/conduit@a1bd348`](https://github.com/timokoesters/conduit/commit/a1bd348) (2023-03)

## What changed vs step 632

| Rust change | C++ translation |
|---|---|
| Fix: history visibility. Fixes for history visibility feature. 3 files changed. | **Translated** — Follows step 625 — fixes for history visibility. |

## Implementation details

- Follows step 625 — fixes for history visibility.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
