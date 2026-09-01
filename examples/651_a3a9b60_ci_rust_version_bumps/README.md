# Step 651 — "chore(ci): Adjust to rust version bumps" (Conduit `a3a9b60`)

Source: [`timokoesters/conduit@a3a9b60`](https://github.com/timokoesters/conduit/commit/a3a9b60) (2023-06)

## What changed vs step 650

| Rust change | C++ translation |
|---|---|
| Chore(ci): Adjust to rust version bumps. CI Rust version updates. 2 files changed. | **No-op for us** — Rust CI version — N/A for C++. |

## Implementation details

- Rust CI version — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
