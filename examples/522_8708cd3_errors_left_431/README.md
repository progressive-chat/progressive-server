# Step 522 — "431 errors left" (Conduit `8708cd3`)

Source: [`timokoesters/conduit@8708cd3`](https://github.com/timokoesters/conduit/commit/8708cd3) (2022-10)

## What changed vs step 521

| Rust change | C++ translation |
|---|---|
| 431 errors left. Progress tracking during refactor. 32 files changed. | **No-op for us** — Rust refactor progress — N/A for C++. |

## Implementation details

- Rust refactor progress — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
